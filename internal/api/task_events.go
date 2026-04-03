package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AutoScan/agentscan/internal/core/logger"
	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func (s *Server) handleListTaskEvents(c *gin.Context) {
	taskID := c.Param("id")
	limit := getIntQuery(c, "limit", 200)
	if limit > 1000 {
		limit = 1000
	}

	if _, err := s.store.GetTask(c.Request.Context(), taskID); err != nil {
		respondError(c, http.StatusNotFound, "task not found")
		return
	}

	events, err := s.store.ListTaskEvents(c.Request.Context(), taskID, limit)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "list task events failed", err.Error())
		return
	}

	if len(events) == 0 {
		events, err = s.synthesizeTaskEvents(c.Request.Context(), taskID, limit)
		if err != nil {
			respondError(c, http.StatusInternalServerError, "build task events failed", err.Error())
			return
		}
	}

	respondOK(c, gin.H{"data": events, "total": len(events)})
}

func (s *Server) persistTaskEvent(ctx context.Context, topic string, payload any, eventTime time.Time) {
	event, ok := s.buildTaskEvent(ctx, topic, payload, eventTime)
	if !ok {
		return
	}
	if err := s.store.CreateTaskEvent(context.Background(), event); err != nil {
		logger.Named("api").Warn("persist task event failed",
			zap.String("topic", topic),
			zap.String("task_id", event.TaskID),
			zap.Error(err),
		)
	}
}

func (s *Server) buildTaskEvent(ctx context.Context, topic string, payload any, eventTime time.Time) (*models.TaskEvent, bool) {
	payloadMap, ok := toJSONMap(payload)
	if !ok {
		return nil, false
	}

	taskID := extractTaskID(topic, payloadMap)
	if taskID == "" {
		return nil, false
	}

	return &models.TaskEvent{
		ID:        uuid.New().String(),
		TaskID:    taskID,
		EventType: topic,
		Summary:   s.buildTaskEventSummary(ctx, topic, payloadMap),
		Payload:   payloadMap,
		EventTime: eventTime,
	}, true
}

func (s *Server) synthesizeTaskEvents(ctx context.Context, taskID string, limit int) ([]models.TaskEvent, error) {
	task, err := s.store.GetTask(ctx, taskID)
	if err != nil {
		return nil, err
	}

	assets, _, err := s.store.ListAssets(ctx, store.AssetFilter{TaskID: taskID, Limit: 10000})
	if err != nil {
		return nil, err
	}
	vulns, _, err := s.store.ListVulnerabilities(ctx, store.VulnFilter{TaskID: taskID, Limit: 10000})
	if err != nil {
		return nil, err
	}

	assetByID := make(map[string]models.Asset, len(assets))
	events := make([]models.TaskEvent, 0, len(assets)+len(vulns)+2)

	for _, asset := range assets {
		assetByID[asset.ID] = asset
		eventTime := asset.LastSeenAt
		if eventTime.IsZero() {
			eventTime = asset.FirstSeenAt
		}

		payload, _ := toJSONMap(asset)
		events = append(events, models.TaskEvent{
			ID:        "synthetic-asset-" + asset.ID,
			TaskID:    taskID,
			EventType: "agent.identified",
			Summary:   summarizeAssetEvent(payload),
			Payload:   payload,
			EventTime: eventTime,
		})
	}

	for _, vuln := range vulns {
		payload, _ := toJSONMap(vuln)
		summary := s.buildTaskEventSummary(ctx, "vuln.detected", payload)
		if asset, ok := assetByID[vuln.AssetID]; ok {
			summary = summarizeVulnEvent(payload, &asset)
		}

		events = append(events, models.TaskEvent{
			ID:        "synthetic-vuln-" + vuln.ID,
			TaskID:    taskID,
			EventType: "vuln.detected",
			Summary:   summary,
			Payload:   payload,
			EventTime: vuln.DetectedAt,
		})
	}

	if task.StartedAt != nil {
		payload, _ := toJSONMap(task)
		events = append(events, models.TaskEvent{
			ID:        "synthetic-start-" + task.ID,
			TaskID:    taskID,
			EventType: "task.started",
			Summary:   fmt.Sprintf("任务开始扫描，目标 %d 个", task.TotalTargets),
			Payload:   payload,
			EventTime: *task.StartedAt,
		})
	}

	if task.FinishedAt != nil {
		payload, _ := toJSONMap(task)
		events = append(events, models.TaskEvent{
			ID:        "synthetic-finish-" + task.ID,
			TaskID:    taskID,
			EventType: "task.completed",
			Summary:   summarizeTaskCompleted(payload),
			Payload:   payload,
			EventTime: *task.FinishedAt,
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].EventTime.After(events[j].EventTime)
	})

	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}

	return events, nil
}

func (s *Server) buildTaskEventSummary(ctx context.Context, topic string, payload models.JSONMap) string {
	switch topic {
	case "task.progress":
		return summarizeProgressEvent(payload)
	case "task.completed":
		return summarizeTaskCompleted(payload)
	case "agent.identified":
		return summarizeAssetEvent(payload)
	case "vuln.detected":
		assetID := getString(payload, "asset_id")
		if assetID != "" {
			if asset, err := s.store.GetAsset(ctx, assetID); err == nil {
				return summarizeVulnEvent(payload, asset)
			}
		}
		return summarizeVulnEvent(payload, nil)
	default:
		return getString(payload, "summary")
	}
}

func extractTaskID(topic string, payload models.JSONMap) string {
	switch topic {
	case "task.progress":
		return getString(payload, "task_id")
	case "task.completed":
		if id := getString(payload, "id"); id != "" {
			return id
		}
		return getString(payload, "task_id")
	case "agent.identified", "vuln.detected":
		return getString(payload, "task_id")
	default:
		return ""
	}
}

func summarizeProgressEvent(payload models.JSONMap) string {
	phase := strings.ToUpper(getString(payload, "phase"))
	scanned := getInt(payload, "scanned")
	total := getInt(payload, "total")
	progress := getFloat(payload, "progress")
	if phase == "" {
		phase = "SCAN"
	}
	return fmt.Sprintf("阶段 %s：已完成 %d/%d，进度 %.0f%%", phase, scanned, total, progress)
}

func summarizeTaskCompleted(payload models.JSONMap) string {
	status := getString(payload, "status")
	if status == "" {
		status = "completed"
	}
	return fmt.Sprintf(
		"任务%s，开放端口 %d，发现 Agent %d，发现漏洞 %d",
		status,
		getInt(payload, "open_ports"),
		getInt(payload, "found_agents"),
		getInt(payload, "found_vulns"),
	)
}

func summarizeAssetEvent(payload models.JSONMap) string {
	parts := []string{
		fmt.Sprintf("发现Agent %s %s:%d", nonEmpty(getString(payload, "agent_type"), "unknown"), getString(payload, "ip"), getInt(payload, "port")),
	}
	if version := getString(payload, "version"); version != "" {
		parts = append(parts, "版本 "+version)
	}
	if authMode := getString(payload, "auth_mode"); authMode != "" {
		parts = append(parts, "认证 "+authMode)
	}
	return strings.Join(parts, "，")
}

func summarizeVulnEvent(payload models.JSONMap, asset *models.Asset) string {
	target := ""
	if asset != nil {
		target = fmt.Sprintf(" %s:%d", asset.IP, asset.Port)
	}
	cveID := getString(payload, "cve_id")
	if cveID == "" {
		cveID = getString(payload, "title")
	}
	return fmt.Sprintf(
		"发现漏洞%s %s，等级 %s，依据 %s",
		target,
		cveID,
		strings.ToUpper(nonEmpty(getString(payload, "severity"), "unknown")),
		nonEmpty(getString(payload, "check_type"), "unknown"),
	)
}

func toJSONMap(value any) (models.JSONMap, bool) {
	if value == nil {
		return nil, false
	}
	if m, ok := value.(models.JSONMap); ok {
		return m, true
	}

	data, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}

	var m models.JSONMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	return m, true
}

func getString(payload models.JSONMap, key string) string {
	value, ok := payload[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func getInt(payload models.JSONMap, key string) int {
	value, ok := payload[key]
	if !ok || value == nil {
		return 0
	}
	switch v := value.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float32:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func getFloat(payload models.JSONMap, key string) float64 {
	value, ok := payload[key]
	if !ok || value == nil {
		return 0
	}
	switch v := value.(type) {
	case float32:
		return float64(v)
	case float64:
		return v
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return 0
	}
}

func nonEmpty(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

package api

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/report"
	"github.com/AutoScan/agentscan/internal/scanner/l3"
	"github.com/AutoScan/agentscan/internal/store"
	"github.com/AutoScan/agentscan/internal/utils/iputil"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
)

// --- Auth ---

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (s *Server) handleLogin(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request", err.Error())
		return
	}

	token, err := s.auth.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		respondError(c, http.StatusUnauthorized, "invalid credentials")
		return
	}

	respondOK(c, gin.H{"token": token})
}

func (s *Server) handleMe(c *gin.Context) {
	respondOK(c, gin.H{
		"user_id":  c.GetString("user_id"),
		"username": c.GetString("username"),
		"role":     c.GetString("role"),
	})
}

// --- Tasks ---

type createTaskRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Targets     string `json:"targets" binding:"required"`
	Ports       string `json:"ports"`
	ScanDepth   string `json:"scan_depth"`
	Type        string `json:"type"`
	CronExpr    string `json:"cron_expr"`
	Concurrency int    `json:"concurrency"`
	Timeout     int    `json:"timeout"`
	EnableMDNS  *bool  `json:"enable_mdns"`
}

func (s *Server) handleCreateTask(c *gin.Context) {
	var req createTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid request", err.Error())
		return
	}

	if req.ScanDepth != "" && req.ScanDepth != "l1" && req.ScanDepth != "l2" && req.ScanDepth != "l3" {
		respondError(c, http.StatusBadRequest, "scan_depth must be l1, l2, or l3")
		return
	}
	if req.Type == "scheduled" && req.CronExpr == "" {
		respondError(c, http.StatusBadRequest, "cron_expr is required for scheduled tasks")
		return
	}
	if req.CronExpr != "" {
		if _, err := cron.ParseStandard(req.CronExpr); err != nil {
			respondError(c, http.StatusBadRequest, "invalid cron expression", err.Error())
			return
		}
	}
	if req.Ports != "" {
		for _, p := range strings.Split(req.Ports, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				respondError(c, http.StatusBadRequest, "invalid port: "+p)
				return
			}
		}
	}

	t := &models.Task{
		Name:        req.Name,
		Description: req.Description,
		Targets:     req.Targets,
		Ports:       req.Ports,
		ScanDepth:   models.ScanDepth(req.ScanDepth),
		Concurrency: req.Concurrency,
		Timeout:     req.Timeout,
		EnableMDNS:  s.cfg.Scanner.EnableMDNS,
	}
	if req.EnableMDNS != nil {
		t.EnableMDNS = *req.EnableMDNS
	}
	if t.ScanDepth == "" {
		t.ScanDepth = models.ScanDepthL3
	}

	if req.Type == "scheduled" {
		t.Type = models.TaskTypeScheduled
		t.CronExpr = req.CronExpr
	} else {
		t.Type = models.TaskTypeInstant
	}

	if err := s.taskMgr.Create(c.Request.Context(), t); err != nil {
		respondError(c, http.StatusInternalServerError, "create task failed", err.Error())
		return
	}

	if t.Type == models.TaskTypeInstant {
		go s.taskMgr.Start(context.Background(), t.ID)
	} else if t.CronExpr != "" {
		s.scheduler.AddTask(t.ID, t.CronExpr)
	}

	respondCreated(c, t)
}

func (s *Server) handleListTasks(c *gin.Context) {
	page, limit, offset := getPagination(c)
	filter := store.TaskFilter{Limit: limit, Offset: offset}
	if status := c.Query("status"); status != "" {
		st := models.TaskStatus(status)
		filter.Status = &st
	}

	tasks, total, err := s.taskMgr.List(c.Request.Context(), filter)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "list tasks failed", err.Error())
		return
	}
	respondPaginated(c, tasks, total, page, limit)
}

func (s *Server) handleGetTask(c *gin.Context) {
	task, err := s.taskMgr.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondError(c, http.StatusNotFound, "task not found")
		return
	}
	respondOK(c, task)
}

type taskTargetStatus struct {
	Target     string           `json:"target"`
	Status     string           `json:"status"`
	StatusText string           `json:"status_text"`
	Summary    string           `json:"summary"`
	AssetID    string           `json:"asset_id,omitempty"`
	IP         string           `json:"ip,omitempty"`
	Port       int              `json:"port,omitempty"`
	AgentType  string           `json:"agent_type,omitempty"`
	Version    string           `json:"version,omitempty"`
	AuthMode   string           `json:"auth_mode,omitempty"`
	RiskLevel  models.RiskLevel `json:"risk_level,omitempty"`
	Confidence float64          `json:"confidence,omitempty"`
	VulnCount  int              `json:"vuln_count,omitempty"`
}

func (s *Server) handleGetTaskTargets(c *gin.Context) {
	task, err := s.taskMgr.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondError(c, http.StatusNotFound, "task not found")
		return
	}

	targets, err := iputil.ParseTargets(task.Targets)
	if err != nil {
		respondError(c, http.StatusBadRequest, "parse targets failed", err.Error())
		return
	}

	assets, _, err := s.store.ListAssets(c.Request.Context(), store.AssetFilter{TaskID: task.ID, Limit: 10000})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "list assets failed", err.Error())
		return
	}
	vulns, _, err := s.store.ListVulnerabilities(c.Request.Context(), store.VulnFilter{TaskID: task.ID, Limit: 10000})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "list vulns failed", err.Error())
		return
	}

	vulnCountByAsset := make(map[string]int, len(vulns))
	for _, vuln := range vulns {
		vulnCountByAsset[vuln.AssetID]++
	}

	assetsByIP := make(map[string][]models.Asset)
	for _, asset := range assets {
		assetsByIP[asset.IP] = append(assetsByIP[asset.IP], asset)
	}

	statuses := make([]taskTargetStatus, 0, len(targets)+len(assets))
	seenTargets := make(map[string]bool, len(targets))
	for _, target := range targets {
		if seenTargets[target] {
			continue
		}
		seenTargets[target] = true

		matchedAssets := assetsByIP[target]
		if len(matchedAssets) == 0 {
			statuses = append(statuses, taskTargetStatus{
				Target:     target,
				Status:     inferNonAssetStatus(task.Status),
				StatusText: inferNonAssetStatusText(task.Status),
				Summary:    inferNonAssetSummary(task.Status),
				IP:         target,
			})
			continue
		}

		for _, asset := range matchedAssets {
			statuses = append(statuses, taskTargetStatus{
				Target:     target,
				Status:     "identified",
				StatusText: "已识别 Agent",
				Summary:    fmt.Sprintf("已识别为 %s 资产", asset.AgentType),
				AssetID:    asset.ID,
				IP:         asset.IP,
				Port:       asset.Port,
				AgentType:  asset.AgentType,
				Version:    asset.Version,
				AuthMode:   asset.AuthMode,
				RiskLevel:  asset.RiskLevel,
				Confidence: asset.Confidence,
				VulnCount:  vulnCountByAsset[asset.ID],
			})
		}
	}

	for _, asset := range assets {
		if seenTargets[asset.IP] {
			continue
		}
		statuses = append(statuses, taskTargetStatus{
			Target:     asset.IP,
			Status:     "out_of_scope",
			StatusText: "不在原始目标中",
			Summary:    "该资产不在任务原始目标中，通常属于历史脏数据或旧版 mDNS 误入结果。",
			AssetID:    asset.ID,
			IP:         asset.IP,
			Port:       asset.Port,
			AgentType:  asset.AgentType,
			Version:    asset.Version,
			AuthMode:   asset.AuthMode,
			RiskLevel:  asset.RiskLevel,
			Confidence: asset.Confidence,
			VulnCount:  vulnCountByAsset[asset.ID],
		})
	}

	respondOK(c, gin.H{"data": statuses, "total": len(statuses)})
}

func inferNonAssetStatus(status models.TaskStatus) string {
	switch status {
	case models.TaskStatusPending, models.TaskStatusPaused:
		return "pending"
	case models.TaskStatusRunning:
		return "scanning"
	default:
		return "scanned_no_agent"
	}
}

func inferNonAssetStatusText(status models.TaskStatus) string {
	switch status {
	case models.TaskStatusPending, models.TaskStatusPaused:
		return "等待扫描"
	case models.TaskStatusRunning:
		return "扫描中"
	default:
		return "未识别 Agent"
	}
}

func inferNonAssetSummary(status models.TaskStatus) string {
	switch status {
	case models.TaskStatusPending, models.TaskStatusPaused:
		return "目标尚未开始扫描。"
	case models.TaskStatusRunning:
		return "目标正在扫描中，当前还没有识别结果。"
	default:
		return "目标已扫描，但未识别到受支持的 Agent。可能端口未开放，或服务不是受支持的 Agent。"
	}
}

func (s *Server) handleDeleteTask(c *gin.Context) {
	if err := s.taskMgr.Delete(c.Request.Context(), c.Param("id")); err != nil {
		respondError(c, http.StatusInternalServerError, "delete failed", err.Error())
		return
	}
	respondMessage(c, "deleted")
}

func (s *Server) handleStartTask(c *gin.Context) {
	if err := s.taskMgr.Start(c.Request.Context(), c.Param("id")); err != nil {
		respondError(c, http.StatusBadRequest, "start failed", err.Error())
		return
	}
	respondMessage(c, "started")
}

func (s *Server) handleStopTask(c *gin.Context) {
	if err := s.taskMgr.Stop(c.Request.Context(), c.Param("id")); err != nil {
		respondError(c, http.StatusBadRequest, "stop failed", err.Error())
		return
	}
	respondMessage(c, "stopped")
}

// --- Assets ---

func (s *Server) handleListAssets(c *gin.Context) {
	page, limit, offset := getPagination(c)
	filter := store.AssetFilter{
		TaskID:    c.Query("task_id"),
		AgentType: c.Query("agent_type"),
		IP:        c.Query("ip"),
		Limit:     limit,
		Offset:    offset,
	}
	if rl := c.Query("risk_level"); rl != "" {
		r := models.RiskLevel(rl)
		filter.RiskLevel = &r
	}

	assets, total, err := s.store.ListAssets(c.Request.Context(), filter)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "list assets failed", err.Error())
		return
	}
	respondPaginated(c, assets, total, page, limit)
}

func (s *Server) handleGetAsset(c *gin.Context) {
	asset, err := s.store.GetAsset(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondError(c, http.StatusNotFound, "asset not found")
		return
	}
	respondOK(c, asset)
}

func (s *Server) handleGetAssetVulns(c *gin.Context) {
	vulns, err := s.store.ListVulnsByAsset(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "list vulns failed", err.Error())
		return
	}
	respondOK(c, gin.H{"data": s.hydrateVulnerabilityViews(c.Request.Context(), vulns)})
}

// --- Vulnerabilities ---

func (s *Server) handleListVulns(c *gin.Context) {
	page, limit, offset := getPagination(c)
	filter := store.VulnFilter{
		TaskID:         c.Query("task_id"),
		AssetID:        c.Query("asset_id"),
		Identifier:     firstNonEmpty(c.Query("identifier"), c.Query("cve_id")),
		IdentifierType: normalizeIdentifierType(c.Query("identifier_type")),
		CheckType:      c.Query("check_type"),
		Limit:          limit,
		Offset:         offset,
	}
	if sev := c.Query("severity"); sev != "" {
		s := models.Severity(sev)
		filter.Severity = &s
	}

	vulns, total, err := s.store.ListVulnerabilities(c.Request.Context(), filter)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "list vulns failed", err.Error())
		return
	}
	views := s.synthesizeTaskAssetContext(c.Request.Context(), filter.TaskID, vulns)
	respondPaginated(c, views, total, page, limit)
}

func (s *Server) handleGetVuln(c *gin.Context) {
	vuln, err := s.store.GetVulnerability(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondError(c, http.StatusNotFound, "vulnerability not found")
		return
	}
	*vuln = l3.LocalizeVulnerability(*vuln)
	views := s.hydrateVulnerabilityViews(c.Request.Context(), []models.Vulnerability{*vuln})
	if len(views) == 0 {
		respondOK(c, vuln)
		return
	}
	respondOK(c, views[0])
}

// --- Dashboard ---

func (s *Server) handleDashboardStats(c *gin.Context) {
	stats, err := s.store.GetDashboardStats(c.Request.Context())
	if err != nil {
		respondError(c, http.StatusInternalServerError, "stats failed", err.Error())
		return
	}
	respondOK(c, stats)
}

// --- Report ---

func (s *Server) handleExportExcel(c *gin.Context) {
	taskID := c.Param("taskId")
	t, err := s.store.GetTask(c.Request.Context(), taskID)
	if err != nil {
		respondError(c, http.StatusNotFound, "task not found")
		return
	}

	assets, _, _ := s.store.ListAssets(c.Request.Context(), store.AssetFilter{TaskID: taskID, Limit: 10000})
	vulns, _, _ := s.store.ListVulnerabilities(c.Request.Context(), store.VulnFilter{TaskID: taskID, Limit: 10000})
	for i := range vulns {
		vulns[i] = l3.LocalizeVulnerability(vulns[i])
	}

	scanTime := t.CreatedAt
	if t.StartedAt != nil {
		scanTime = *t.StartedAt
	}

	f, err := report.GenerateExcel(report.ExcelReportData{
		TaskName:        t.Name,
		ScanTime:        scanTime,
		TotalTargets:    t.TotalTargets,
		OpenPorts:       t.OpenPorts,
		Assets:          assets,
		Vulnerabilities: vulns,
		RuleCatalog:     l3.GetRuleCatalogMetadata(),
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "generate report failed", err.Error())
		return
	}

	filename := fmt.Sprintf("GateScope_Report_%s_%s.xlsx", t.Name, time.Now().Format("20060102"))
	c.Header("Content-Disposition", buildDownloadDisposition(filename))
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	f.Write(c.Writer)
}

func (s *Server) handleRuleCatalog(c *gin.Context) {
	respondOK(c, l3.GetRuleCatalogMetadata())
}

func (s *Server) handleRuleCatalogEntries(c *gin.Context) {
	entries := l3.GetRuleCatalogEntries()
	respondOK(c, gin.H{"data": entries, "total": len(entries)})
}

func buildDownloadDisposition(filename string) string {
	base := filepath.Base(strings.TrimSpace(filename))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "report.xlsx"
	}

	fallback := make([]rune, 0, len(base))
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z':
			fallback = append(fallback, r)
		case r >= 'A' && r <= 'Z':
			fallback = append(fallback, r)
		case r >= '0' && r <= '9':
			fallback = append(fallback, r)
		case strings.ContainsRune("._-()", r):
			fallback = append(fallback, r)
		default:
			fallback = append(fallback, '_')
		}
	}

	fallbackName := strings.TrimSpace(string(fallback))
	if fallbackName == "" {
		fallbackName = "report.xlsx"
	}

	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, fallbackName, url.PathEscape(base))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func normalizeIdentifierType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "cve", "cnnvd":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

// --- Dashboard Trends ---

func (s *Server) handleDashboardTrends(c *gin.Context) {
	tasks, _, _ := s.store.ListTasks(c.Request.Context(), store.TaskFilter{Limit: 30})

	type point struct {
		Date   string `json:"date"`
		Assets int    `json:"assets"`
		Vulns  int    `json:"vulns"`
	}

	dateMap := make(map[string]*point)
	for _, t := range tasks {
		d := t.CreatedAt.Format("01-02")
		if _, ok := dateMap[d]; !ok {
			dateMap[d] = &point{Date: d}
		}
		dateMap[d].Assets += t.FoundAgents
		dateMap[d].Vulns += t.FoundVulns
	}

	var points []point
	for _, p := range dateMap {
		points = append(points, *p)
	}
	respondOK(c, gin.H{"data": points})
}

// --- File Import ---

func (s *Server) handleImportTargets(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		respondError(c, http.StatusBadRequest, "file required")
		return
	}

	f, err := file.Open()
	if err != nil {
		respondError(c, http.StatusInternalServerError, "cannot open file")
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	var targets []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, ','); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		targets = append(targets, line)
	}

	if len(targets) == 0 {
		respondError(c, http.StatusBadRequest, "no valid targets found in file")
		return
	}

	respondOK(c, gin.H{
		"targets": strings.Join(targets, ","),
		"count":   len(targets),
		"message": fmt.Sprintf("Parsed %d targets from file", len(targets)),
	})
}

// --- Frontend ---

func (s *Server) serveFrontend() gin.HandlerFunc {
	if s.frontendFS == nil {
		return func(c *gin.Context) {
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.String(http.StatusOK, fallbackHTML)
		}
	}

	fileServer := http.FileServer(http.FS(s.frontendFS))

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		if f, err := s.frontendFS.Open(strings.TrimPrefix(path, "/")); err == nil {
			f.Close()
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		// SPA fallback: serve index.html directly to avoid FileServer redirecting /index.html -> ./
		data, err := fs.ReadFile(s.frontendFS, "index.html")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	}
}

var fallbackHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>GateScope</title></head>
<body><div id="root"><h2 style="text-align:center;margin-top:100px">GateScope API Server Running</h2><p style="text-align:center">Frontend not embedded. Build with: cd web && npm run build && go build</p></div></body>
</html>`

func getIntQuery(c *gin.Context, key string, def int) int {
	if v := c.Query(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/AutoScan/agentscan/internal/core/eventbus"
	"github.com/AutoScan/agentscan/internal/core/logger"
	"github.com/AutoScan/agentscan/internal/models"
	"github.com/google/uuid"
)

type RuleCondition string

const (
	CondAlways         RuleCondition = "always"
	CondSeverityGte    RuleCondition = "severity_gte"
	CondRiskGte        RuleCondition = "risk_gte"
	CondNewAgent       RuleCondition = "new_agent"
	CondUnauthAgent    RuleCondition = "unauth_agent"
	CondMaliciousSkill RuleCondition = "malicious_skill"
	CondTaskCompleted  RuleCondition = "task_completed"
)

type AlertRuleDTO struct {
	Name      string        `json:"name"`
	Event     string        `json:"event"`
	Condition RuleCondition `json:"condition"`
	Threshold string        `json:"threshold"`
	Enabled   bool          `json:"enabled"`
}

type RuleStore interface {
	ListAlertRules(ctx context.Context) ([]models.AlertRule, error)
	SaveAlertRules(ctx context.Context, rules []models.AlertRule) error
	CreateAlertRecord(ctx context.Context, record *models.AlertRecord) error
	ListAlertRecords(ctx context.Context, limit int) ([]models.AlertRecord, error)
}

type Engine struct {
	webhookURL string
	timeout    time.Duration
	enabled    bool
	client     *http.Client
	store      RuleStore
	rules      []AlertRuleDTO
	mu         sync.RWMutex
}

func NewEngine(webhookURL string, timeout time.Duration, enabled bool, store RuleStore) *Engine {
	e := &Engine{
		webhookURL: webhookURL,
		timeout:    timeout,
		enabled:    enabled,
		client:     &http.Client{Timeout: timeout},
		store:      store,
	}
	e.loadRulesFromDB()
	return e
}

func (e *Engine) loadRulesFromDB() {
	if e.store == nil {
		e.rules = defaultRules()
		return
	}
	dbRules, err := e.store.ListAlertRules(context.Background())
	if err != nil || len(dbRules) == 0 {
		e.rules = defaultRules()
		return
	}
	e.rules = make([]AlertRuleDTO, len(dbRules))
	for i, r := range dbRules {
		e.rules[i] = AlertRuleDTO{
			Name: r.Name, Event: r.Event,
			Condition: RuleCondition(r.Condition),
			Threshold: r.Threshold, Enabled: r.Enabled,
		}
	}
}

func defaultRules() []AlertRuleDTO {
	return []AlertRuleDTO{
		{Name: "新Agent发现", Event: "agent.identified", Condition: CondNewAgent, Enabled: true},
		{Name: "无认证Agent", Event: "agent.identified", Condition: CondUnauthAgent, Enabled: true},
		{Name: "严重漏洞", Event: "vuln.detected", Condition: CondSeverityGte, Threshold: "critical", Enabled: true},
		{Name: "高危漏洞", Event: "vuln.detected", Condition: CondSeverityGte, Threshold: "high", Enabled: true},
		{Name: "任务完成", Event: "task.completed", Condition: CondTaskCompleted, Enabled: false},
	}
}

func (e *Engine) GetRules() []AlertRuleDTO {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rules := make([]AlertRuleDTO, len(e.rules))
	copy(rules, e.rules)
	return rules
}

func (e *Engine) SetRules(rules []AlertRuleDTO) {
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()

	if e.store != nil {
		dbRules := make([]models.AlertRule, len(rules))
		for i, r := range rules {
			dbRules[i] = models.AlertRule{
				ID: uuid.New().String(), Name: r.Name, Event: r.Event,
				Condition: string(r.Condition), Threshold: r.Threshold, Enabled: r.Enabled,
			}
		}
		_ = e.store.SaveAlertRules(context.Background(), dbRules)
	}
}

func (e *Engine) GetHistory(limit int) ([]models.AlertRecord, error) {
	if e.store == nil {
		return nil, nil
	}
	return e.store.ListAlertRecords(context.Background(), limit)
}

func (e *Engine) RegisterHandlers(bus eventbus.EventBus) {
	bus.Subscribe(eventbus.TopicAgentIdentified, func(ctx context.Context, ev eventbus.Event) {
		if asset, ok := ev.Payload.(models.Asset); ok {
			data := map[string]any{
				"ip": asset.IP, "port": asset.Port,
				"agent_type": asset.AgentType, "version": asset.Version,
				"risk_level": asset.RiskLevel, "auth_mode": asset.AuthMode,
			}
			e.evaluate("agent.identified", data, &asset, nil)
		}
	})

	bus.Subscribe(eventbus.TopicVulnDetected, func(ctx context.Context, ev eventbus.Event) {
		if vuln, ok := ev.Payload.(models.Vulnerability); ok {
			data := map[string]any{
				"cve_id": vuln.CVEID, "title": vuln.Title,
				"severity": vuln.Severity, "cvss": vuln.CVSS,
				"asset_id": vuln.AssetID, "check_type": vuln.CheckType,
			}
			e.evaluate("vuln.detected", data, nil, &vuln)
		}
	})

	bus.Subscribe(eventbus.TopicTaskCompleted, func(ctx context.Context, ev eventbus.Event) {
		if task, ok := ev.Payload.(*models.Task); ok {
			data := map[string]any{
				"task_id": task.ID, "name": task.Name, "status": task.Status,
				"found_agents": task.FoundAgents, "found_vulns": task.FoundVulns,
			}
			e.evaluate("task.completed", data, nil, nil)
		}
	})
}

func (e *Engine) evaluate(event string, data map[string]any, asset *models.Asset, vuln *models.Vulnerability) {
	e.mu.RLock()
	rules := make([]AlertRuleDTO, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled || rule.Event != event {
			continue
		}
		if e.matchRule(rule, asset, vuln) {
			e.fire(rule, event, data)
		}
	}
}

func (e *Engine) matchRule(rule AlertRuleDTO, asset *models.Asset, vuln *models.Vulnerability) bool {
	switch rule.Condition {
	case CondAlways:
		return true
	case CondNewAgent:
		return asset != nil
	case CondUnauthAgent:
		if asset == nil {
			return false
		}
		return asset.AuthMode == "none" || asset.AuthMode == "open" || asset.AuthMode == ""
	case CondSeverityGte:
		if vuln == nil {
			return false
		}
		return sevLevel(vuln.Severity) >= sevLevel(models.Severity(rule.Threshold))
	case CondRiskGte:
		if asset == nil {
			return false
		}
		return riskLevel(asset.RiskLevel) >= riskLevel(models.RiskLevel(rule.Threshold))
	case CondTaskCompleted:
		return true
	default:
		return false
	}
}

func (e *Engine) fire(rule AlertRuleDTO, eventType string, data map[string]any) {
	record := models.AlertRecord{
		ID:        uuid.New().String(),
		EventType: eventType,
		RuleName:  rule.Name,
		Data:      models.JSONMap(data),
	}

	if e.enabled && e.webhookURL != "" {
		err := e.sendWebhook(eventType, data)
		record.Sent = err == nil
		if err != nil {
			record.Error = err.Error()
		}
	}

	if e.store != nil {
		_ = e.store.CreateAlertRecord(context.Background(), &record)
	}
}

type WebhookPayload struct {
	EventType string         `json:"event_type"`
	Timestamp string         `json:"timestamp"`
	Data      map[string]any `json:"data"`
	Source    string         `json:"source"`
}

func (e *Engine) sendWebhook(eventType string, data map[string]any) error {
	payload := WebhookPayload{
		EventType: eventType,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      data,
		Source:    "GateScope",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	resp, err := e.client.Post(e.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func (e *Engine) SetWebhookURL(url string) {
	e.webhookURL = url
	e.enabled = url != ""
}

func (e *Engine) TestWebhook() error {
	if e.webhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}
	err := e.sendWebhook("test", map[string]any{"message": "GateScope webhook test"})
	if err != nil {
		logger.S().Warnw("test webhook failed", "error", err)
	}
	return err
}

var sevMap = map[models.Severity]int{
	models.SeverityInfo: 0, models.SeverityLow: 1, models.SeverityMedium: 2,
	models.SeverityHigh: 3, models.SeverityCritical: 4,
}

func sevLevel(s models.Severity) int {
	if v, ok := sevMap[s]; ok {
		return v
	}
	return -1
}

var riskMap = map[models.RiskLevel]int{
	models.RiskInfo: 0, models.RiskLow: 1, models.RiskMedium: 2,
	models.RiskHigh: 3, models.RiskCritical: 4,
}

func riskLevel(r models.RiskLevel) int {
	if v, ok := riskMap[r]; ok {
		return v
	}
	return -1
}

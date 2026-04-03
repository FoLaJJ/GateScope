package l2

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/AutoScan/agentscan/internal/scanner"
)

var (
	versionRegex = regexp.MustCompile(`[Oo]pen[Cc]law\s+v?(\d{4}\.\d+\.\d+)`)
	htmlTitleRe  = regexp.MustCompile(`(?i)<title>\s*(OpenClaw[^<]*)</title>`)
	htmlAppRe    = regexp.MustCompile(`(?i)<openclaw-app`)
	htmlClawRe   = regexp.MustCompile(`(?i)(openclaw|clawdbot|openmolt|龙虾)`)
)

type HTTPProber struct {
	Client    *http.Client
	TLSClient *http.Client
	Timeout   time.Duration
}

func NewHTTPProber(timeout time.Duration) *HTTPProber {
	return &HTTPProber{
		Client: &http.Client{Timeout: timeout},
		TLSClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		Timeout: timeout,
	}
}

func (p *HTTPProber) ProbeHealth(ip string, port int) scanner.ProbeResult {
	start := time.Now()
	result := scanner.ProbeResult{
		Type:    "http_health",
		Details: make(map[string]string),
	}

	url := fmt.Sprintf("http://%s:%d/health", ip, port)
	resp, err := p.Client.Get(url)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Success = true

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		result.Error = "read body: " + err.Error()
		return result
	}
	result.Details["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
	result.Details["body"] = string(body)

	for _, h := range []string{"X-OpenClaw-Version", "X-OpenClaw-AgentId"} {
		if v := resp.Header.Get(h); v != "" {
			result.Details[h] = v
		}
	}

	var healthResp map[string]any
	if err := json.Unmarshal(body, &healthResp); err == nil {
		if matchOpenClawHealth(healthResp) {
			result.Matched = true
			result.Details["agent_type"] = "openclaw"
			if v, ok := healthResp["version"].(string); ok {
				result.Details["version"] = v
			}
			if v, ok := healthResp["auth_mode"].(string); ok {
				result.Details["auth_mode"] = v
			}
			if v, ok := healthResp["agent_id"].(string); ok {
				result.Details["agent_id"] = v
			}
		}
	}

	if !result.Matched {
		if m := versionRegex.FindStringSubmatch(string(body)); len(m) > 1 {
			result.Matched = true
			result.Details["agent_type"] = "openclaw"
			result.Details["version"] = m[1]
		}
	}

	return result
}

func (p *HTTPProber) ProbeReady(ip string, port int) scanner.ProbeResult {
	start := time.Now()
	result := scanner.ProbeResult{
		Type:    "http_ready",
		Details: make(map[string]string),
	}

	url := fmt.Sprintf("http://%s:%d/health/ready", ip, port)
	resp, err := p.Client.Get(url)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Success = true

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		result.Error = "read body: " + err.Error()
		return result
	}
	result.Details["status_code"] = fmt.Sprintf("%d", resp.StatusCode)

	var readyResp map[string]any
	if err := json.Unmarshal(body, &readyResp); err == nil {
		if _, hasReady := readyResp["ready"]; hasReady {
			if channels, ok := readyResp["channels"]; ok {
				result.Matched = true
				result.Details["agent_type"] = "openclaw"
				if chMap, ok := channels.(map[string]any); ok {
					var chNames []string
					for name := range chMap {
						chNames = append(chNames, name)
					}
					result.Details["channels"] = strings.Join(chNames, ",")
				}
			}
		}
	}

	// SPA fallback: /health/ready returns HTML with OpenClaw title → confirms OpenClaw
	if !result.Matched && strings.Contains(string(body), "<openclaw-app") {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["spa_fallback"] = "true"
	}

	return result
}

func (p *HTTPProber) ProbeRootHTML(ip string, port int) scanner.ProbeResult {
	start := time.Now()
	result := scanner.ProbeResult{
		Type:    "http_html",
		Details: make(map[string]string),
	}

	url := fmt.Sprintf("http://%s:%d/", ip, port)
	resp, err := p.Client.Get(url)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Success = true

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		result.Error = "read body: " + err.Error()
		return result
	}
	result.Details["status_code"] = fmt.Sprintf("%d", resp.StatusCode)

	for _, h := range []string{"X-OpenClaw-Version", "X-OpenClaw-AgentId", "Server"} {
		if v := resp.Header.Get(h); v != "" {
			result.Details[h] = v
		}
	}

	// CSP header analysis: ws: wss: in connect-src is a strong signal
	if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
		if strings.Contains(csp, "ws:") || strings.Contains(csp, "wss:") {
			result.Details["csp_websocket"] = "true"
		}
	}

	bodyStr := string(body)

	if m := versionRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["version"] = m[1]
		return result
	}

	if m := htmlTitleRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["html_title"] = m[1]
	}

	if htmlAppRe.MatchString(bodyStr) {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["web_component"] = "openclaw-app"
	}

	if !result.Matched && htmlClawRe.MatchString(bodyStr) {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["brand_match"] = htmlClawRe.FindString(bodyStr)
	}

	return result
}

// ProbeMCP probes GET /mcp — OpenClaw exposes this endpoint for MCP protocol.
func (p *HTTPProber) ProbeMCP(ip string, port int) scanner.ProbeResult {
	start := time.Now()
	result := scanner.ProbeResult{
		Type:    "http_mcp",
		Details: make(map[string]string),
	}

	url := fmt.Sprintf("http://%s:%d/mcp", ip, port)
	resp, err := p.Client.Get(url)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Success = true

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		result.Error = "read body: " + err.Error()
		return result
	}
	result.Details["status_code"] = fmt.Sprintf("%d", resp.StatusCode)

	if resp.StatusCode == 200 {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "openclaw-app") ||
			strings.Contains(bodyStr, "OpenClaw") {
			result.Matched = true
			result.Details["agent_type"] = "openclaw"
			result.Details["mcp_endpoint"] = "active"
		}

		if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
			if strings.Contains(csp, "ws:") {
				result.Details["csp_websocket"] = "true"
			}
		}
	}

	return result
}

// ProbeControlUIConfig fetches /__openclaw/control-ui-config.json which
// exposes serverVersion, assistantName, and other metadata without auth.
func (p *HTTPProber) ProbeControlUIConfig(ip string, port int) scanner.ProbeResult {
	start := time.Now()
	result := scanner.ProbeResult{
		Type:    "http_config",
		Details: make(map[string]string),
	}

	url := fmt.Sprintf("http://%s:%d/__openclaw/control-ui-config.json", ip, port)
	resp, err := p.Client.Get(url)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.Success = true

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		result.Error = "read body: " + err.Error()
		return result
	}
	result.Details["status_code"] = fmt.Sprintf("%d", resp.StatusCode)

	if resp.StatusCode != 200 {
		return result
	}

	var config struct {
		ServerVersion    string `json:"serverVersion"`
		AssistantName    string `json:"assistantName"`
		AssistantAvatar  string `json:"assistantAvatar"`
		AssistantAgentID string `json:"assistantAgentId"`
		BasePath         string `json:"basePath"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		return result
	}

	if config.ServerVersion != "" {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["version"] = config.ServerVersion
	}
	if config.AssistantName != "" {
		result.Details["assistant_name"] = config.AssistantName
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
	}
	if config.AssistantAgentID != "" {
		result.Details["agent_id"] = config.AssistantAgentID
	}

	return result
}

func (p *HTTPProber) ProbeTLS(ip string, port int) scanner.ProbeResult {
	start := time.Now()
	result := scanner.ProbeResult{
		Type:    "tls_cert",
		Details: make(map[string]string),
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: p.Timeout},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
	result.Success = true

	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Details["subject_cn"] = cert.Subject.CommonName
		result.Details["issuer_cn"] = cert.Issuer.CommonName
		result.Details["not_after"] = cert.NotAfter.Format("2006-01-02")

		if len(cert.DNSNames) > 0 {
			result.Details["san_dns"] = strings.Join(cert.DNSNames, ",")
		}

		certStr := strings.ToLower(cert.Subject.CommonName + " " +
			cert.Issuer.CommonName + " " + strings.Join(cert.DNSNames, " "))
		if strings.Contains(certStr, "openclaw") ||
			strings.Contains(certStr, "clawdbot") {
			result.Matched = true
			result.Details["agent_type"] = "openclaw"
		}

		isSelfSigned := cert.Subject.CommonName == cert.Issuer.CommonName
		if isSelfSigned {
			result.Details["self_signed"] = "true"
		}
	}

	result.Details["tls_version"] = fmt.Sprintf("0x%04x", state.Version)
	result.Details["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)

	return result
}

func matchOpenClawHealth(data map[string]any) bool {
	// Pattern 1: rich format with agent_id, auth_mode, tools_loaded
	clawKeys := []string{"agent_id", "auth_mode", "tools_loaded"}
	matchCount := 0
	for _, key := range clawKeys {
		if _, ok := data[key]; ok {
			matchCount++
		}
	}
	if matchCount >= 2 {
		return true
	}

	// Pattern 2: rich format with status + version + agent_id
	if status, ok := data["status"].(string); ok {
		if strings.EqualFold(status, "ok") {
			if _, hasVersion := data["version"]; hasVersion {
				if _, hasAgent := data["agent_id"]; hasAgent {
					return true
				}
			}
		}
	}

	// Pattern 3: real-world minimal format {"ok":true,"status":"live"}
	if okVal, hasOk := data["ok"]; hasOk {
		if okBool, isBool := okVal.(bool); isBool && okBool {
			if status, hasStatus := data["status"].(string); hasStatus {
				if status == "live" || status == "ok" {
					return true
				}
			}
		}
	}

	return false
}

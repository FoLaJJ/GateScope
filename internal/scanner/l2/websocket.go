package l2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/AutoScan/agentscan/internal/scanner"
	"github.com/gorilla/websocket"
)

type WSProber struct {
	Timeout time.Duration
}

func NewWSProber(timeout time.Duration) *WSProber {
	return &WSProber{Timeout: timeout}
}

// OpenClaw gateway WS protocol frames
type wsMessage struct {
	Type    string          `json:"type"`
	Event   string          `json:"event,omitempty"`
	ID      string          `json:"id,omitempty"`
	OK      *bool           `json:"ok,omitempty"`
	Method  string          `json:"method,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type challengePayload struct {
	Nonce string `json:"nonce"`
	TS    int64  `json:"ts"`
}

// hello-ok payload returned by the gateway after successful connect
type helloOKPayload struct {
	Type     string `json:"type"` // "hello-ok"
	Protocol int    `json:"protocol"`
	Policy   struct {
		TickIntervalMs int `json:"tickIntervalMs"`
	} `json:"policy"`
	Auth *struct {
		DeviceToken string   `json:"deviceToken"`
		Role        string   `json:"role"`
		Scopes      []string `json:"scopes"`
	} `json:"auth,omitempty"`
}

// Probe connects to the OpenClaw Gateway WS endpoint, reads the first
// server message (connect.challenge), and optionally sends a connect
// request to extract server capabilities.
//
// Per the official protocol docs, the WS endpoint is at the root path /.
// Ref: https://docs.openclaw.ai/gateway/protocol
func (p *WSProber) Probe(ip string, port int) scanner.ProbeResult {
	start := time.Now()
	result := scanner.ProbeResult{
		Type:    "websocket",
		Details: make(map[string]string),
	}

	// Root path is the official endpoint; /ws as fallback.
	// Do NOT send an Origin header — per source code, any request with
	// an Origin header triggers browser origin enforcement for all client IDs.
	paths := []string{"/", "/ws"}
	var conn *websocket.Conn
	var resp *http.Response
	var dialErr error

	dialer := websocket.Dialer{HandshakeTimeout: p.Timeout}

	for _, path := range paths {
		url := fmt.Sprintf("ws://%s:%d%s", ip, port, path)
		conn, resp, dialErr = dialer.Dial(url, nil)
		if dialErr == nil {
			result.Details["ws_path"] = path
			break
		}
		if resp != nil {
			extractWSHeaders(resp.Header, &result)
		}
	}

	result.Duration = time.Since(start)
	if dialErr != nil {
		if resp != nil {
			result.Success = true
		} else {
			result.Error = dialErr.Error()
		}
		return result
	}
	defer conn.Close()
	result.Success = true

	if resp != nil {
		extractWSHeaders(resp.Header, &result)
	}

	// Read the first server message — OpenClaw sends connect.challenge
	conn.SetReadDeadline(time.Now().Add(p.Timeout))
	_, msgBytes, err := conn.ReadMessage()
	if err != nil {
		result.Details["ws_read_err"] = err.Error()
		return result
	}

	var msg wsMessage
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		result.Details["ws_first_msg"] = truncate(string(msgBytes), 200)
		return result
	}

	result.Details["ws_msg_type"] = msg.Type

	// connect.challenge is the OpenClaw gateway's signature handshake.
	// This alone is a strong, version-universal fingerprint.
	if msg.Type == "event" && msg.Event == "connect.challenge" {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["ws_event"] = "connect.challenge"

		var challenge challengePayload
		if err := json.Unmarshal(msg.Payload, &challenge); err == nil {
			result.Details["ws_nonce"] = challenge.Nonce
		}

		// Attempt connect request with ed25519 device signing
		cr := p.sendConnectRequest(conn, challenge.Nonce)
		if cr.HelloOK != nil {
			result.Details["protocol"] = fmt.Sprintf("%d", cr.HelloOK.Protocol)
			result.Details["ws_auth"] = "open"
			if cr.HelloOK.Policy.TickIntervalMs > 0 {
				result.Details["tick_interval"] = fmt.Sprintf("%dms", cr.HelloOK.Policy.TickIntervalMs)
			}
		} else {
			if cr.RejectCode != "" {
				result.Details["ws_reject_code"] = cr.RejectCode
			}
			if cr.RejectMsg != "" {
				result.Details["ws_reject_msg"] = cr.RejectMsg
			}
			// Classify auth/security posture from rejection
			msg := strings.ToLower(cr.RejectMsg)
			code := strings.ToLower(cr.RejectCode)
			switch {
			case strings.Contains(msg, "origin not allowed"):
				result.Details["ws_auth"] = "origin_restricted"
			case strings.Contains(msg, "device nonce") || strings.Contains(code, "device_auth"):
				result.Details["ws_auth"] = "device_auth"
			case strings.HasPrefix(code, "auth_"):
				result.Details["ws_auth"] = "token_auth"
			case cr.RejectMsg == "no_response":
				result.Details["ws_auth"] = "connection_closed"
			}
		}
	}

	return result
}

type connectResponse struct {
	HelloOK    *helloOKPayload
	RejectCode string
	RejectMsg  string
}

// sendConnectRequest sends an operator connect request with ed25519 device signing.
func (p *WSProber) sendConnectRequest(conn *websocket.Conn, nonce string) connectResponse {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return connectResponse{RejectMsg: "keygen failed"}
	}

	rawPub := []byte(pub)
	deviceId := hex.EncodeToString(sha256Sum(rawPub))
	pubKeyB64 := base64UrlEncode(rawPub)

	clientId := "openclaw-probe"
	clientMode := "probe"
	role := "operator"
	scopes := []string{"operator.read"}
	platform := "linux"
	signedAt := time.Now().UnixMilli()

	// v3 signing payload
	payload := strings.Join([]string{
		"v3",
		deviceId,
		clientId,
		clientMode,
		role,
		strings.Join(scopes, ","),
		fmt.Sprintf("%d", signedAt),
		"", // no token
		nonce,
		platform,
		"", // no deviceFamily
	}, "|")

	sig := ed25519.Sign(priv, []byte(payload))
	sigB64 := base64UrlEncode(sig)

	connectReq := map[string]any{
		"type":   "req",
		"id":     "agentscan-probe-001",
		"method": "connect",
		"params": map[string]any{
			"minProtocol": 3,
			"maxProtocol": 3,
			"client": map[string]any{
				"id":         clientId,
				"version":    "0.1.0",
				"platform":   platform,
				"mode":       clientMode,
				"instanceId": fmt.Sprintf("agentscan-%d", signedAt),
			},
			"role":      role,
			"scopes":    scopes,
			"caps":      []string{},
			"locale":    "en",
			"userAgent": "AgentScan/0.1.0",
			"device": map[string]any{
				"id":        deviceId,
				"publicKey": pubKeyB64,
				"signature": sigB64,
				"signedAt":  signedAt,
				"nonce":     nonce,
			},
		},
	}

	conn.SetWriteDeadline(time.Now().Add(p.Timeout))
	if err := conn.WriteJSON(connectReq); err != nil {
		return connectResponse{}
	}

	conn.SetReadDeadline(time.Now().Add(p.Timeout))
	_, respBytes, err := conn.ReadMessage()
	if err != nil {
		return connectResponse{RejectMsg: "no_response"}
	}

	// Try multiple response formats:
	// 1. {"type":"res","ok":true,"payload":{"type":"hello-ok",...}}
	// 2. {"type":"res","ok":false,"error":{"message":"...","details":{...}}}
	// 3. {"type":"res","id":"...","ok":false,"payload":{"message":"..."}}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return connectResponse{RejectMsg: truncate(string(respBytes), 200)}
	}

	// Check ok field
	var okField bool
	if okRaw, exists := raw["ok"]; exists {
		json.Unmarshal(okRaw, &okField)
	}

	// Success path
	if okField {
		if payloadRaw, exists := raw["payload"]; exists {
			var payload helloOKPayload
			if err := json.Unmarshal(payloadRaw, &payload); err == nil && payload.Type == "hello-ok" {
				return connectResponse{HelloOK: &payload}
			}
		}
	}

	// Error path — try "error" field first, then "payload" as error
	type errorDetail struct {
		Message string `json:"message"`
		Details struct {
			Code                string `json:"code"`
			Reason              string `json:"reason"`
			RecommendedNextStep string `json:"recommendedNextStep"`
		} `json:"details"`
	}

	if errRaw, exists := raw["error"]; exists {
		var ed errorDetail
		if err := json.Unmarshal(errRaw, &ed); err == nil && ed.Message != "" {
			code := ed.Details.Code
			if code == "" {
				code = ed.Details.Reason
			}
			return connectResponse{RejectCode: code, RejectMsg: ed.Message}
		}
	}

	// Fallback: return truncated raw response
	return connectResponse{RejectMsg: truncate(string(respBytes), 300)}
}

func extractWSHeaders(h http.Header, result *scanner.ProbeResult) {
	if v := h.Get("X-OpenClaw-Version"); v != "" {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["version"] = v
	}
	if v := h.Get("X-OpenClaw-AgentId"); v != "" {
		result.Details["agent_id"] = v
		result.Matched = true
	}
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func base64UrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

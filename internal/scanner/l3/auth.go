package l3

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type AuthCheckResult struct {
	AuthMode    string
	Severity    string
	Description string
	Evidence    string
}

func CheckAuth(ip string, port int, timeout time.Duration) AuthCheckResult {
	client := &http.Client{Timeout: timeout}

	url := fmt.Sprintf("http://%s:%d/health", ip, port)
	resp, err := client.Get(url)
	if err != nil {
		return AuthCheckResult{
			AuthMode:    "unknown",
			Severity:    "info",
			Description: "Cannot determine authentication status",
			Evidence:    fmt.Sprintf("url=%s error=%v", url, err),
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var health map[string]any
	if err := json.Unmarshal(body, &health); err != nil {
		return AuthCheckResult{
			AuthMode:    "unknown",
			Severity:    "info",
			Description: "Non-JSON health response",
			Evidence:    fmt.Sprintf("url=%s status=%d body=%s", url, resp.StatusCode, strings.TrimSpace(string(body))),
		}
	}

	authMode := "unknown"
	if am, ok := health["auth_mode"].(string); ok {
		authMode = am
	}
	evidence := fmt.Sprintf("url=%s status=%d auth_mode=%s", url, resp.StatusCode, authMode)

	switch authMode {
	case "none", "open":
		return AuthCheckResult{
			AuthMode:    authMode,
			Severity:    "critical",
			Description: "Agent has NO authentication - fully accessible to anyone on the network",
			Evidence:    evidence,
		}
	case "token":
		return AuthCheckResult{
			AuthMode:    authMode,
			Severity:    "low",
			Description: "Token-based authentication enabled",
			Evidence:    evidence,
		}
	case "device_auth":
		return AuthCheckResult{
			AuthMode:    authMode,
			Severity:    "low",
			Description: "Device-based authentication (ed25519) enabled",
			Evidence:    evidence,
		}
	default:
		return AuthCheckResult{
			AuthMode:    authMode,
			Severity:    "medium",
			Description: "Unknown authentication mode",
			Evidence:    evidence,
		}
	}
}

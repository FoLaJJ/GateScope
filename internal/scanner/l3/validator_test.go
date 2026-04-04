package l3

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type validatorTestServerOptions struct {
	authMode string
	wsOK     bool
	fetchOK  bool
	avatarOK bool
}

func TestValidate_PoCSuccessSuppressesVersionDuplicate(t *testing.T) {
	useRepositoryRules(t)

	ip, port, closeServer := startValidatorTestServer(t, validatorTestServerOptions{
		authMode: "token_auth",
		fetchOK:  true,
	})
	defer closeServer()

	output := Validate(ValidationInput{
		IP:        ip,
		Port:      port,
		AgentType: "openclaw",
		Version:   "2026.2.13",
		TaskID:    "task-1",
		AssetID:   "asset-1",
	}, ValidatorConfig{
		Timeout:   2 * time.Second,
		EnablePoC: true,
	})

	require.True(t, hasMatchedCVE(output.CVEResults, "CVE-2026-26324"))

	hits := vulnerabilitiesByCVE(output, "CVE-2026-26324")
	require.Len(t, hits, 1)
	assert.Equal(t, "poc_verify", hits[0].CheckType)
	assert.Contains(t, hits[0].Title, "[PoC]")
}

func TestValidate_FallsBackToVersionMatchWhenPoCFails(t *testing.T) {
	useRepositoryRules(t)

	ip, port, closeServer := startValidatorTestServer(t, validatorTestServerOptions{
		authMode: "device_auth",
		wsOK:     false,
		fetchOK:  false,
	})
	defer closeServer()

	output := Validate(ValidationInput{
		IP:        ip,
		Port:      port,
		AgentType: "openclaw",
		Version:   "2026.2.13",
		TaskID:    "task-2",
		AssetID:   "asset-2",
	}, ValidatorConfig{
		Timeout:   2 * time.Second,
		EnablePoC: true,
	})

	require.True(t, hasMatchedCVE(output.CVEResults, "CVE-2026-26324"))

	hits := vulnerabilitiesByCVE(output, "CVE-2026-26324")
	require.Len(t, hits, 1)
	assert.Equal(t, "cve_match", hits[0].CheckType)
	assert.NotContains(t, hits[0].Title, "[PoC]")
}

func startValidatorTestServer(t *testing.T, opts validatorTestServerOptions) (string, int, func()) {
	t.Helper()

	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"status":    "live",
			"version":   "2026.2.20",
			"auth_mode": opts.authMode,
		})
	})

	mux.HandleFunc("/api/skills", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	})

	mux.HandleFunc("/api/fetch", func(w http.ResponseWriter, r *http.Request) {
		if !opts.fetchOK {
			http.NotFound(w, r)
			return
		}

		target := r.URL.Query().Get("url")
		if !strings.Contains(target, "[0:0:0:0:0:ffff:7f00:1]") || !strings.HasSuffix(target, "/health") {
			http.NotFound(w, r)
			return
		}

		resp, err := http.Get("http://127.0.0.1:" + portFromHost(t, r.Host) + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})

	mux.HandleFunc("/__openclaw/control-ui-config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"serverVersion":    "2026.2.20",
			"assistantAgentId": "main",
			"basePath":         "",
		})
	})

	mux.HandleFunc("/avatar/main", func(w http.ResponseWriter, r *http.Request) {
		if !opts.avatarOK {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("root:x:0:0:avatar-secret"))
	})

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !opts.wsOK {
			http.NotFound(w, r)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{
			"type":    "event",
			"event":   "connect.challenge",
			"payload": map[string]any{"nonce": "test"},
		})
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()

	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)

	return host, port, server.Close
}

func portFromHost(t *testing.T, host string) string {
	t.Helper()

	_, port, err := net.SplitHostPort(host)
	require.NoError(t, err)
	return port
}

func vulnerabilitiesByCVE(output ValidationOutput, cveID string) []stringVulnerability {
	hits := make([]stringVulnerability, 0)
	for _, vuln := range output.Vulnerabilities {
		if vuln.CVEID == cveID {
			hits = append(hits, stringVulnerability{
				Title:     vuln.Title,
				CheckType: vuln.CheckType,
			})
		}
	}
	return hits
}

type stringVulnerability struct {
	Title     string
	CheckType string
}

func hasMatchedCVE(results []CVEMatchResult, cveID string) bool {
	for _, result := range results {
		if (result.CVE.ID == cveID || result.CVE.CVEID == cveID) && result.Matched {
			return true
		}
	}
	return false
}

func useRepositoryRules(t *testing.T) {
	t.Helper()

	prevDir, hadPrevDir := os.LookupEnv("AGENTSCAN_RULES_DIR")
	require.NoError(t, os.Unsetenv("AGENTSCAN_RULES_DIR"))
	resetLoadedRulesForTests()

	t.Cleanup(func() {
		if hadPrevDir {
			_ = os.Setenv("AGENTSCAN_RULES_DIR", prevDir)
		} else {
			_ = os.Unsetenv("AGENTSCAN_RULES_DIR")
		}
		resetLoadedRulesForTests()
	})
}

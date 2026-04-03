package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/mdns"
)

var (
	port       = flag.Int("port", 18789, "listen port")
	version    = flag.String("version", "2026.3.13", "simulated OpenClaw version")
	agentID    = flag.String("agent-id", "mock-abc-123-def", "simulated agent ID")
	auth       = flag.String("auth", "none", "auth mode: none|token|oauth")
	enableMDNS = flag.Bool("mdns", true, "enable mDNS service advertisement")
)

var startTime = time.Now()

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func main() {
	flag.Parse()

	if *enableMDNS {
		go startMDNS()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/ws", handleWS)
	mux.HandleFunc("/mcp", handleMCP)
	mux.HandleFunc("/__openclaw/control-ui-config.json", handleControlUIConfig)
	mux.HandleFunc("/api/skills", handleSkills)
	mux.HandleFunc("/api/v1/skills", handleSkills)
	mux.HandleFunc("/", handleRootOrWS)

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	log.Printf("[mock-openclaw] listening on %s  version=%s  agent_id=%s  auth=%s  mdns=%v",
		addr, *version, *agentID, *auth, *enableMDNS)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func startMDNS() {
	host, _ := os.Hostname()
	info := []string{
		fmt.Sprintf("version=%s", *version),
		fmt.Sprintf("id=%s", *agentID),
	}

	ips := getLocalIPs()
	log.Printf("[mdns] advertising _openclaw-gw._tcp on port %d, IPs=%v", *port, ips)

	service, err := mdns.NewMDNSService(host, "_openclaw-gw._tcp", "", "", *port, ips, info)
	if err != nil {
		log.Printf("[mdns] service creation failed: %v", err)
		return
	}

	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		log.Printf("[mdns] server start failed: %v", err)
		return
	}
	_ = server
	log.Printf("[mdns] service registered: %s._openclaw-gw._tcp.local:%d", host, *port)
}

func getLocalIPs() []net.IP {
	var ips []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil && !strings.HasPrefix(ipnet.IP.String(), "169.254") {
				ips = append(ips, ipnet.IP)
			}
		}
	}
	return ips
}

// handleHealth mimics the real OpenClaw health response (rich format).
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-OpenClaw-Version", *version)
	w.Header().Set("X-OpenClaw-AgentId", *agentID)
	json.NewEncoder(w).Encode(map[string]any{
		"status":       "ok",
		"version":      *version,
		"agent_id":     *agentID,
		"auth_mode":    *auth,
		"tools_loaded": 5,
		"uptime_s":     int(time.Since(startTime).Seconds()),
	})
}

// handleWS implements the real OpenClaw gateway WS protocol:
// 1. Server sends connect.challenge with nonce
// 2. Client replies with connect request
// 3. Server replies with connect response containing server info
func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	nonce := uuid.New().String()
	challenge := map[string]any{
		"type":  "event",
		"event": "connect.challenge",
		"payload": map[string]any{
			"nonce": nonce,
			"ts":    time.Now().UnixMilli(),
		},
	}
	if err := conn.WriteJSON(challenge); err != nil {
		return
	}
	log.Printf("[ws] sent connect.challenge nonce=%s", nonce)

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var req struct {
			Type   string `json:"type"`
			ID     string `json:"id"`
			Method string `json:"method"`
			Params struct {
				MinProtocol int `json:"minProtocol"`
				MaxProtocol int `json:"maxProtocol"`
				Client      struct {
					ID      string `json:"id"`
					Version string `json:"version"`
				} `json:"client"`
				Role   string   `json:"role"`
				Scopes []string `json:"scopes"`
			} `json:"params"`
		}
		if err := json.Unmarshal(msgBytes, &req); err != nil {
			continue
		}

		if req.Type == "req" && req.Method == "connect" {
			log.Printf("[ws] connect from client=%s version=%s role=%s",
				req.Params.Client.ID, req.Params.Client.Version, req.Params.Role)

			okTrue := true
			resp := map[string]any{
				"type": "res",
				"id":   req.ID,
				"ok":   okTrue,
				"payload": map[string]any{
					"type":     "hello-ok",
					"protocol": 3,
					"policy": map[string]any{
						"tickIntervalMs": 15000,
					},
				},
			}
			conn.WriteJSON(resp)
		}
	}
}

// handleRootOrWS routes WebSocket upgrades to WS handler, normal HTTP to SPA.
func handleRootOrWS(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") == "websocket" {
		handleWS(w, r)
		return
	}
	handleSPA(w, r)
}

func handleControlUIConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{
		"basePath":         "",
		"assistantName":    "Mock Agent",
		"assistantAvatar":  "🤖",
		"assistantAgentId": *agentID,
		"serverVersion":    *version,
	})
}

func handleSkills(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode([]map[string]string{
		{"name": "@openclaw/web-search", "version": "1.2.0", "author": "OpenClaw", "description": "Web search tool"},
		{"name": "@openclaw/file-manager", "version": "1.0.3", "author": "OpenClaw", "description": "File system operations"},
		{"name": "@openclaw/code-runner", "version": "2.1.0", "author": "OpenClaw", "description": "Execute code in sandbox"},
		{"name": "@community/weather", "version": "0.5.0", "author": "community", "description": "Weather forecast"},
		{"name": "custom-data-tool", "version": "", "author": "", "description": "Custom data processing"},
	})
}

func handleMCP(w http.ResponseWriter, r *http.Request) {
	handleSPA(w, r)
}

func handleSPA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; connect-src 'self' ws: wss:; script-src 'self'; style-src 'self' 'unsafe-inline'")
	w.Header().Set("Cache-Control", "no-cache")

	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>OpenClaw Control</title>
  </head>
  <body>
    <openclaw-app></openclaw-app>
  </body>
</html>`)
}

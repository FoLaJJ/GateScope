package intel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Provider interface {
	Name() string
	Search(query string, limit int) ([]IntelResult, error)
}

type IntelResult struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Title    string `json:"title"`
	Banner   string `json:"banner"`
	Country  string `json:"country"`
	City     string `json:"city"`
	Source   string `json:"source"`
}

type FOFAClient struct {
	Email  string
	APIKey string
	client *http.Client
}

func NewFOFAClient(email, apiKey string) *FOFAClient {
	return &FOFAClient{
		Email:  email,
		APIKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *FOFAClient) Name() string { return "fofa" }

func (f *FOFAClient) Search(query string, limit int) ([]IntelResult, error) {
	if f.Email == "" || f.APIKey == "" {
		return nil, fmt.Errorf("FOFA credentials not configured")
	}
	if limit <= 0 {
		limit = 100
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(query))
	apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d&fields=ip,port,protocol,host,title,banner,country,city",
		url.QueryEscape(f.Email), url.QueryEscape(f.APIKey), encoded, limit)

	resp, err := f.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("fofa request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var fofaResp struct {
		Error   bool       `json:"error"`
		ErrMsg  string     `json:"errmsg"`
		Size    int        `json:"size"`
		Results [][]string `json:"results"`
	}
	if err := json.Unmarshal(body, &fofaResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if fofaResp.Error {
		return nil, fmt.Errorf("fofa error: %s", fofaResp.ErrMsg)
	}

	var results []IntelResult
	for _, row := range fofaResp.Results {
		if len(row) < 8 {
			continue
		}
		port := 0
		fmt.Sscanf(row[1], "%d", &port)
		results = append(results, IntelResult{
			IP: row[0], Port: port, Protocol: row[2],
			Host: row[3], Title: row[4], Banner: row[5],
			Country: row[6], City: row[7], Source: "fofa",
		})
	}
	return results, nil
}

func DefaultOpenClawQuery() string {
	return `title="OpenClaw" || body="openclaw-app" || body="agent_id" && body="auth_mode" || header="X-OpenClaw-Version"`
}

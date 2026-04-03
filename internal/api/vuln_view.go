package api

import (
	"context"
	"fmt"

	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/scanner/l3"
	"github.com/AutoScan/agentscan/internal/store"
)

type vulnerabilityView struct {
	models.Vulnerability
	AssetIP      string `json:"asset_ip,omitempty"`
	AssetPort    int    `json:"asset_port,omitempty"`
	AgentType    string `json:"agent_type,omitempty"`
	AssetVersion string `json:"asset_version,omitempty"`
	AuthMode     string `json:"auth_mode,omitempty"`
	RiskLevel    string `json:"risk_level,omitempty"`
	AssetLabel   string `json:"asset_label,omitempty"`
}

func (s *Server) hydrateVulnerabilityViews(ctx context.Context, vulns []models.Vulnerability) []vulnerabilityView {
	if len(vulns) == 0 {
		return []vulnerabilityView{}
	}

	views := make([]vulnerabilityView, 0, len(vulns))
	assetCache := make(map[string]models.Asset)
	missing := make(map[string]struct{})

	for _, vuln := range vulns {
		vuln = l3.LocalizeVulnerability(vuln)
		view := vulnerabilityView{Vulnerability: vuln}
		if vuln.AssetID != "" {
			asset, ok := assetCache[vuln.AssetID]
			if !ok {
				if _, skipped := missing[vuln.AssetID]; !skipped {
					if loaded, err := s.store.GetAsset(ctx, vuln.AssetID); err == nil {
						asset = *loaded
						assetCache[vuln.AssetID] = asset
						ok = true
					} else {
						missing[vuln.AssetID] = struct{}{}
					}
				}
			}

			if ok {
				view.AssetIP = asset.IP
				view.AssetPort = asset.Port
				view.AgentType = asset.AgentType
				view.AssetVersion = asset.Version
				view.AuthMode = asset.AuthMode
				view.RiskLevel = string(asset.RiskLevel)
				view.AssetLabel = assetLabel(asset, vuln.AssetID)
			}
		}
		views = append(views, view)
	}

	return views
}

func assetLabel(asset models.Asset, fallbackID string) string {
	endpoint := ""
	if asset.IP != "" {
		endpoint = fmt.Sprintf("%s:%d", asset.IP, asset.Port)
	}
	if endpoint != "" && asset.AgentType != "" {
		return fmt.Sprintf("%s (%s)", endpoint, asset.AgentType)
	}
	if endpoint != "" {
		return endpoint
	}
	if fallbackID != "" {
		return fallbackID
	}
	return "-"
}

func (s *Server) synthesizeTaskAssetContext(ctx context.Context, taskID string, vulns []models.Vulnerability) []vulnerabilityView {
	if taskID == "" || len(vulns) == 0 {
		return s.hydrateVulnerabilityViews(ctx, vulns)
	}

	assets, _, err := s.store.ListAssets(ctx, store.AssetFilter{TaskID: taskID, Limit: 10000})
	if err != nil || len(assets) == 0 {
		return s.hydrateVulnerabilityViews(ctx, vulns)
	}

	assetByID := make(map[string]models.Asset, len(assets))
	for _, asset := range assets {
		assetByID[asset.ID] = asset
	}

	views := make([]vulnerabilityView, 0, len(vulns))
	for _, vuln := range vulns {
		vuln = l3.LocalizeVulnerability(vuln)
		view := vulnerabilityView{Vulnerability: vuln}
		if asset, ok := assetByID[vuln.AssetID]; ok {
			view.AssetIP = asset.IP
			view.AssetPort = asset.Port
			view.AgentType = asset.AgentType
			view.AssetVersion = asset.Version
			view.AuthMode = asset.AuthMode
			view.RiskLevel = string(asset.RiskLevel)
			view.AssetLabel = assetLabel(asset, vuln.AssetID)
		}
		views = append(views, view)
	}

	return views
}

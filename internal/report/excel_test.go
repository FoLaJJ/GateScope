package report

import (
	"testing"
	"time"

	"github.com/AutoScan/agentscan/internal/models"
	"github.com/xuri/excelize/v2"
)

func TestGenerateExcelIncludesAssetContextForVulnerabilities(t *testing.T) {
	scanTime := time.Date(2026, 4, 2, 13, 0, 0, 0, time.UTC)
	asset := models.Asset{
		ID:        "asset-1",
		IP:        "192.168.79.134",
		Port:      18789,
		AgentType: "openclaw",
		RiskLevel: models.RiskHigh,
	}
	vuln := models.Vulnerability{
		ID:            "vuln-1",
		AssetID:       asset.ID,
		CVEID:         "CVE-2026-25253",
		Title:         "WebSocket Origin Bypass",
		DescriptionZH: "中文漏洞描述",
		Description:   "English vulnerability description",
		Severity:      models.SeverityHigh,
		CheckType:     "poc_verify",
		Remediation:   "Upgrade immediately",
		DetectedAt:    scanTime,
	}

	f, err := GenerateExcel(ExcelReportData{
		TaskName:        "demo",
		ScanTime:        scanTime,
		TotalTargets:    1,
		OpenPorts:       1,
		Assets:          []models.Asset{asset},
		Vulnerabilities: []models.Vulnerability{vuln},
	})
	if err != nil {
		t.Fatalf("GenerateExcel returned error: %v", err)
	}

	assertCell(t, f, "漏洞详情", "A2", "192.168.79.134")
	assertCell(t, f, "漏洞详情", "B2", "18789")
	assertCell(t, f, "漏洞详情", "E2", "CVE-2026-25253")
	assertCell(t, f, "漏洞详情", "J2", "PoC实证")
	assertCell(t, f, "漏洞详情", "K2", "中文漏洞描述")
	assertCell(t, f, "漏洞详情", "L2", "English vulnerability description")
	assertCell(t, f, "修复清单", "B2", "192.168.79.134")
	assertCell(t, f, "修复清单", "K2", "192.168.79.134:18789 (openclaw)")
}

func assertCell(t *testing.T, f *excelize.File, sheet, cell, want string) {
	t.Helper()
	got, err := f.GetCellValue(sheet, cell)
	if err != nil {
		t.Fatalf("GetCellValue(%s, %s) returned error: %v", sheet, cell, err)
	}
	if got != want {
		t.Fatalf("GetCellValue(%s, %s) = %q, want %q", sheet, cell, got, want)
	}
}

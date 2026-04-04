package report

import (
	"fmt"
	"time"

	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/scanner/l3"
	"github.com/xuri/excelize/v2"
)

type ExcelReportData struct {
	TaskName        string
	ScanTime        time.Time
	TotalTargets    int
	OpenPorts       int
	Assets          []models.Asset
	Vulnerabilities []models.Vulnerability
	RuleCatalog     l3.RuleCatalogMetadata
}

var (
	riskOrder = []models.RiskLevel{models.RiskCritical, models.RiskHigh, models.RiskMedium, models.RiskLow, models.RiskInfo}
	riskNames = map[models.RiskLevel]string{
		models.RiskCritical: "严重", models.RiskHigh: "高危",
		models.RiskMedium: "中危", models.RiskLow: "低危", models.RiskInfo: "信息",
	}
	sevOrder = []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo}
	sevNames = map[models.Severity]string{
		models.SeverityCritical: "严重", models.SeverityHigh: "高危",
		models.SeverityMedium: "中危", models.SeverityLow: "低危", models.SeverityInfo: "信息",
	}
)

func GenerateExcel(data ExcelReportData) (*excelize.File, error) {
	f := excelize.NewFile()
	assetIndex := buildAssetIndex(data.Assets)

	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 18, Color: "#1F4E79"},
	})
	subtitleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 12, Color: "#2E75B6"},
	})
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 11, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#2E75B6"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border:    []excelize.Border{{Type: "bottom", Color: "#1F4E79", Style: 2}},
	})
	criticalStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#C00000"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	highStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#ED7D31"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	medStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "#7F6000"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#FFF2CC"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	lowStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "#375623"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E2EFDA"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	infoStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Color: "#1F4E79"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#DAEEF3"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})

	riskStyleMap := map[string]int{
		"critical": criticalStyle, "high": highStyle, "medium": medStyle, "low": lowStyle, "info": infoStyle,
	}
	labelStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "#2E75B6"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#D6E4F0"}, Pattern: 1},
	})
	wrapStyle, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{WrapText: true, Vertical: "top"},
	})

	// ===== Overview Sheet =====
	sheet := "扫描概况"
	f.SetSheetName("Sheet1", sheet)
	f.SetColWidth(sheet, "A", "A", 20)
	f.SetColWidth(sheet, "B", "B", 40)

	f.SetCellValue(sheet, "A1", "GateScope 安全扫描报告")
	f.SetCellStyle(sheet, "A1", "A1", titleStyle)
	f.MergeCell(sheet, "A1", "B1")

	f.SetCellValue(sheet, "A2", fmt.Sprintf("生成时间: %s", time.Now().Format("2006-01-02 15:04:05")))

	summaryData := [][]string{
		{"任务名称", data.TaskName},
		{"扫描时间", data.ScanTime.Format("2006-01-02 15:04:05")},
		{"目标总数", fmt.Sprintf("%d", data.TotalTargets)},
		{"开放端口", fmt.Sprintf("%d", data.OpenPorts)},
		{"发现Agent", fmt.Sprintf("%d", len(data.Assets))},
		{"发现漏洞", fmt.Sprintf("%d", len(data.Vulnerabilities))},
	}
	if data.RuleCatalog.UpdatedAt != "" {
		summaryData = append(summaryData, []string{"漏洞库更新时间", data.RuleCatalog.UpdatedAt})
	}
	if data.RuleCatalog.SourceCutoff != "" {
		summaryData = append(summaryData, []string{"漏洞库上游截止", data.RuleCatalog.SourceCutoff})
	}
	if data.RuleCatalog.CVECount > 0 || data.RuleCatalog.PoCCount > 0 {
		summaryData = append(summaryData, []string{"规则库规模", fmt.Sprintf("规则 %d / CVE %d / CNNVD %d / PoC %d", data.RuleCatalog.RuleCount, data.RuleCatalog.CVECount, data.RuleCatalog.CNNVDCount, data.RuleCatalog.PoCCount)})
	}
	for i, row := range summaryData {
		r := i + 4
		f.SetCellValue(sheet, fmt.Sprintf("A%d", r), row[0])
		f.SetCellStyle(sheet, fmt.Sprintf("A%d", r), fmt.Sprintf("A%d", r), labelStyle)
		f.SetCellValue(sheet, fmt.Sprintf("B%d", r), row[1])
	}

	riskDist := map[models.RiskLevel]int{}
	for _, a := range data.Assets {
		riskDist[a.RiskLevel]++
	}
	row := len(summaryData) + 6
	f.SetCellValue(sheet, fmt.Sprintf("A%d", row), "风险分布")
	f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), subtitleStyle)
	row++
	for _, level := range riskOrder {
		f.SetCellValue(sheet, fmt.Sprintf("A%d", row), riskNames[level])
		f.SetCellValue(sheet, fmt.Sprintf("B%d", row), riskDist[level])
		if st, ok := riskStyleMap[string(level)]; ok {
			f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), st)
		}
		row++
	}

	sevDist := map[models.Severity]int{}
	for _, v := range data.Vulnerabilities {
		sevDist[v.Severity]++
	}
	row += 2
	f.SetCellValue(sheet, fmt.Sprintf("A%d", row), "漏洞严重等级分布")
	f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), subtitleStyle)
	row++
	for _, sev := range sevOrder {
		f.SetCellValue(sheet, fmt.Sprintf("A%d", row), sevNames[sev])
		f.SetCellValue(sheet, fmt.Sprintf("B%d", row), sevDist[sev])
		if st, ok := riskStyleMap[string(sev)]; ok {
			f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), st)
		}
		row++
	}

	checkTypeDist := map[string]int{}
	for _, v := range data.Vulnerabilities {
		checkTypeDist[v.CheckType]++
	}
	row += 2
	f.SetCellValue(sheet, fmt.Sprintf("A%d", row), "判定依据分布")
	f.SetCellStyle(sheet, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), subtitleStyle)
	row++
	checkLabels := map[string]string{
		"cve_match": "版本匹配", "auth_check": "认证检查",
		"skills_check": "暴露面检查", "poc_verify": "PoC实证",
	}
	for ct, count := range checkTypeDist {
		label := checkLabels[ct]
		if label == "" {
			label = ct
		}
		f.SetCellValue(sheet, fmt.Sprintf("A%d", row), label)
		f.SetCellValue(sheet, fmt.Sprintf("B%d", row), count)
		row++
	}

	// ===== Assets Sheet =====
	assetSheet := "资产清单"
	f.NewSheet(assetSheet)
	assetHeaders := []string{"IP", "端口", "Agent类型", "版本", "认证模式", "风险等级", "置信度", "Agent ID", "国家", "城市", "首次发现", "最后发现"}
	for i, h := range assetHeaders {
		cell := colName(i) + "1"
		f.SetCellValue(assetSheet, cell, h)
		f.SetCellStyle(assetSheet, cell, cell, headerStyle)
	}
	for i, a := range data.Assets {
		r := i + 2
		f.SetCellValue(assetSheet, fmt.Sprintf("A%d", r), a.IP)
		f.SetCellValue(assetSheet, fmt.Sprintf("B%d", r), a.Port)
		f.SetCellValue(assetSheet, fmt.Sprintf("C%d", r), valueOrDefault(a.AgentType, "未识别"))
		f.SetCellValue(assetSheet, fmt.Sprintf("D%d", r), valueOrDefault(a.Version, "未查明"))
		f.SetCellValue(assetSheet, fmt.Sprintf("E%d", r), valueOrDefault(a.AuthMode, "未查明"))
		f.SetCellValue(assetSheet, fmt.Sprintf("F%d", r), string(a.RiskLevel))
		riskCell := fmt.Sprintf("F%d", r)
		if st, ok := riskStyleMap[string(a.RiskLevel)]; ok {
			f.SetCellStyle(assetSheet, riskCell, riskCell, st)
		}
		f.SetCellValue(assetSheet, fmt.Sprintf("G%d", r), fmt.Sprintf("%.0f%%", a.Confidence))
		f.SetCellValue(assetSheet, fmt.Sprintf("H%d", r), valueOrDefault(a.AgentID, "未识别"))
		f.SetCellValue(assetSheet, fmt.Sprintf("I%d", r), valueOrDefault(a.Country, "未获取到"))
		f.SetCellValue(assetSheet, fmt.Sprintf("J%d", r), valueOrDefault(a.City, "未获取到"))
		f.SetCellValue(assetSheet, fmt.Sprintf("K%d", r), formatTime(a.FirstSeenAt))
		f.SetCellValue(assetSheet, fmt.Sprintf("L%d", r), formatTime(a.LastSeenAt))
	}
	f.SetColWidth(assetSheet, "A", "L", 16)

	// ===== Vulnerabilities Sheet =====
	vulnSheet := "漏洞详情"
	f.NewSheet(vulnSheet)
	vulnHeaders := []string{"IP", "端口", "Agent类型", "资产定位", "CVE编号", "CNNVD编号", "标题", "严重等级", "CVSS", "判定依据", "中文描述", "英文描述", "修复建议", "证据", "检测时间"}
	for i, h := range vulnHeaders {
		cell := colName(i) + "1"
		f.SetCellValue(vulnSheet, cell, h)
		f.SetCellStyle(vulnSheet, cell, cell, headerStyle)
	}
	for i, v := range data.Vulnerabilities {
		r := i + 2
		asset := assetIndex[v.AssetID]
		f.SetCellValue(vulnSheet, fmt.Sprintf("A%d", r), asset.IP)
		f.SetCellValue(vulnSheet, fmt.Sprintf("B%d", r), asset.Port)
		f.SetCellValue(vulnSheet, fmt.Sprintf("C%d", r), valueOrDefault(asset.AgentType, "未识别"))
		f.SetCellValue(vulnSheet, fmt.Sprintf("D%d", r), formatAssetLabel(asset, v.AssetID))
		f.SetCellValue(vulnSheet, fmt.Sprintf("E%d", r), valueOrDefault(v.CVEID, describeInternalFinding(v.CheckType)))
		f.SetCellValue(vulnSheet, fmt.Sprintf("F%d", r), valueOrDefault(v.CNNVDID, "暂无对应CNNVD"))
		f.SetCellValue(vulnSheet, fmt.Sprintf("G%d", r), valueOrDefault(v.Title, "未识别漏洞标题"))
		f.SetCellValue(vulnSheet, fmt.Sprintf("H%d", r), string(v.Severity))
		sevCell := fmt.Sprintf("H%d", r)
		if st, ok := riskStyleMap[string(v.Severity)]; ok {
			f.SetCellStyle(vulnSheet, sevCell, sevCell, st)
		}
		f.SetCellValue(vulnSheet, fmt.Sprintf("I%d", r), v.CVSS)
		ctLabel := checkLabels[v.CheckType]
		if ctLabel == "" {
			ctLabel = v.CheckType
		}
		f.SetCellValue(vulnSheet, fmt.Sprintf("J%d", r), ctLabel)
		f.SetCellValue(vulnSheet, fmt.Sprintf("K%d", r), valueOrDefault(v.DescriptionZH, "未提供中文描述"))
		f.SetCellStyle(vulnSheet, fmt.Sprintf("K%d", r), fmt.Sprintf("K%d", r), wrapStyle)
		f.SetCellValue(vulnSheet, fmt.Sprintf("L%d", r), valueOrDefault(v.Description, "No English description available"))
		f.SetCellStyle(vulnSheet, fmt.Sprintf("L%d", r), fmt.Sprintf("L%d", r), wrapStyle)
		f.SetCellValue(vulnSheet, fmt.Sprintf("M%d", r), valueOrDefault(v.Remediation, "未提供修复建议"))
		f.SetCellStyle(vulnSheet, fmt.Sprintf("M%d", r), fmt.Sprintf("M%d", r), wrapStyle)
		f.SetCellValue(vulnSheet, fmt.Sprintf("N%d", r), valueOrDefault(v.Evidence, "未采集到证据"))
		f.SetCellStyle(vulnSheet, fmt.Sprintf("N%d", r), fmt.Sprintf("N%d", r), wrapStyle)
		f.SetCellValue(vulnSheet, fmt.Sprintf("O%d", r), formatTime(v.DetectedAt))
	}
	f.SetColWidth(vulnSheet, "A", "A", 18)
	f.SetColWidth(vulnSheet, "B", "B", 10)
	f.SetColWidth(vulnSheet, "C", "D", 18)
	f.SetColWidth(vulnSheet, "E", "F", 18)
	f.SetColWidth(vulnSheet, "G", "G", 35)
	f.SetColWidth(vulnSheet, "H", "J", 14)
	f.SetColWidth(vulnSheet, "K", "M", 40)
	f.SetColWidth(vulnSheet, "N", "N", 60)
	f.SetColWidth(vulnSheet, "O", "O", 16)

	// ===== Remediation Sheet =====
	remSheet := "修复清单"
	f.NewSheet(remSheet)
	remHeaders := []string{"优先级", "IP", "端口", "Agent类型", "CVE编号", "CNNVD编号", "漏洞标题", "严重等级", "CVSS", "修复建议", "影响资产"}
	for i, h := range remHeaders {
		cell := colName(i) + "1"
		f.SetCellValue(remSheet, cell, h)
		f.SetCellStyle(remSheet, cell, cell, headerStyle)
	}

	priority := 1
	for _, sev := range sevOrder {
		for _, v := range data.Vulnerabilities {
			if v.Severity != sev {
				continue
			}
			asset := assetIndex[v.AssetID]
			r := priority + 1
			f.SetCellValue(remSheet, fmt.Sprintf("A%d", r), priority)
			f.SetCellValue(remSheet, fmt.Sprintf("B%d", r), asset.IP)
			f.SetCellValue(remSheet, fmt.Sprintf("C%d", r), asset.Port)
			f.SetCellValue(remSheet, fmt.Sprintf("D%d", r), valueOrDefault(asset.AgentType, "未识别"))
			f.SetCellValue(remSheet, fmt.Sprintf("E%d", r), valueOrDefault(v.CVEID, describeInternalFinding(v.CheckType)))
			f.SetCellValue(remSheet, fmt.Sprintf("F%d", r), valueOrDefault(v.CNNVDID, "暂无对应CNNVD"))
			f.SetCellValue(remSheet, fmt.Sprintf("G%d", r), valueOrDefault(v.Title, "未识别漏洞标题"))
			f.SetCellValue(remSheet, fmt.Sprintf("H%d", r), string(v.Severity))
			if st, ok := riskStyleMap[string(v.Severity)]; ok {
				f.SetCellStyle(remSheet, fmt.Sprintf("H%d", r), fmt.Sprintf("H%d", r), st)
			}
			f.SetCellValue(remSheet, fmt.Sprintf("I%d", r), v.CVSS)
			f.SetCellValue(remSheet, fmt.Sprintf("J%d", r), valueOrDefault(v.Remediation, "未提供修复建议"))
			f.SetCellStyle(remSheet, fmt.Sprintf("J%d", r), fmt.Sprintf("J%d", r), wrapStyle)
			f.SetCellValue(remSheet, fmt.Sprintf("K%d", r), formatAssetLabel(asset, v.AssetID))
			priority++
		}
	}
	f.SetColWidth(remSheet, "A", "A", 8)
	f.SetColWidth(remSheet, "B", "B", 18)
	f.SetColWidth(remSheet, "C", "C", 10)
	f.SetColWidth(remSheet, "D", "F", 18)
	f.SetColWidth(remSheet, "G", "G", 35)
	f.SetColWidth(remSheet, "H", "I", 12)
	f.SetColWidth(remSheet, "J", "J", 45)
	f.SetColWidth(remSheet, "K", "K", 28)

	return f, nil
}

func buildAssetIndex(assets []models.Asset) map[string]models.Asset {
	assetIndex := make(map[string]models.Asset, len(assets))
	for _, asset := range assets {
		assetIndex[asset.ID] = asset
	}
	return assetIndex
}

func formatAssetLabel(asset models.Asset, fallbackID string) string {
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
	return "未关联到资产"
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "未获取到"
	}
	return t.Format("2006-01-02 15:04")
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func describeInternalFinding(checkType string) string {
	switch checkType {
	case "auth_check", "skills_check":
		return "内置暴露检查，无对应CVE"
	case "poc_verify":
		return "PoC已命中，但未提供外部编号"
	default:
		return "暂无漏洞编号"
	}
}

func colName(i int) string {
	if i < 26 {
		return string(rune('A' + i))
	}
	return string(rune('A'+i/26-1)) + string(rune('A'+i%26))
}

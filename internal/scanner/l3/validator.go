package l3

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/AutoScan/agentscan/internal/models"
	"github.com/google/uuid"
)

type ValidatorConfig struct {
	Timeout   time.Duration
	EnablePoC bool
}

type ValidationInput struct {
	IP        string
	Port      int
	AgentType string
	Version   string
	AuthMode  string
	TaskID    string
	AssetID   string
}

type ValidationOutput struct {
	Vulnerabilities []models.Vulnerability
	AuthResult      AuthCheckResult
	SkillsResult    SkillsCheckResult
	CVEResults      []CVEMatchResult
	PoCResults      []PoCResult
}

func Validate(input ValidationInput, cfg ValidatorConfig) ValidationOutput {
	output := ValidationOutput{}

	if input.AgentType == "openclaw" && input.Version != "" {
		output.CVEResults = MatchCVEs(input.Version)
		for _, cr := range output.CVEResults {
			if cr.Matched {
				output.Vulnerabilities = append(output.Vulnerabilities, models.Vulnerability{
					ID:          uuid.New().String(),
					AssetID:     input.AssetID,
					TaskID:      input.TaskID,
					CVEID:       cr.CVE.ID,
					Title:       cr.CVE.Title,
					Severity:    models.Severity(cr.CVE.Severity),
					CVSS:        cr.CVE.CVSS,
					Description: cr.CVE.Description,
					Remediation: cr.CVE.Remediation,
					Evidence:    cr.Evidence,
					CheckType:   "cve_match",
				})
			}
		}
	}

	output.AuthResult = CheckAuth(input.IP, input.Port, cfg.Timeout)
	if output.AuthResult.Severity == "critical" {
		output.Vulnerabilities = append(output.Vulnerabilities, models.Vulnerability{
			ID:          uuid.New().String(),
			AssetID:     input.AssetID,
			TaskID:      input.TaskID,
			Title:       "No Authentication Configured",
			Severity:    models.SeverityCritical,
			CVSS:        9.0,
			Description: output.AuthResult.Description,
			Evidence:    output.AuthResult.Evidence,
			CheckType:   "auth_check",
			Remediation: "Enable authentication: set auth_mode to 'token_auth' or 'device_auth'",
		})
	} else if output.AuthResult.Severity == "medium" {
		output.Vulnerabilities = append(output.Vulnerabilities, models.Vulnerability{
			ID:          uuid.New().String(),
			AssetID:     input.AssetID,
			TaskID:      input.TaskID,
			Title:       fmt.Sprintf("Weak Authentication Mode: %s", output.AuthResult.AuthMode),
			Severity:    models.SeverityMedium,
			CVSS:        5.3,
			Description: output.AuthResult.Description,
			Evidence:    output.AuthResult.Evidence,
			CheckType:   "auth_check",
			Remediation: "Consider upgrading to 'device_auth' (ed25519) for stronger authentication",
		})
	}

	output.SkillsResult = CheckSkills(input.IP, input.Port, cfg.Timeout)
	if output.SkillsResult.Accessible && output.SkillsResult.TotalSkills > 0 {
		evidence, _ := json.Marshal(output.SkillsResult.Skills)

		severity := models.SeverityMedium
		cvss := 5.3
		if output.AuthResult.AuthMode == "none" || output.AuthResult.AuthMode == "open" {
			severity = models.SeverityHigh
			cvss = 7.5
		}

		output.Vulnerabilities = append(output.Vulnerabilities, models.Vulnerability{
			ID:          uuid.New().String(),
			AssetID:     input.AssetID,
			TaskID:      input.TaskID,
			Title:       fmt.Sprintf("Skills Enumeration: %d skills exposed", output.SkillsResult.TotalSkills),
			Severity:    severity,
			CVSS:        cvss,
			Description: "Agent skills list is publicly accessible, exposing installed capabilities",
			Evidence:    string(evidence),
			CheckType:   "skills_check",
			Remediation: "Restrict skills endpoint with authentication; audit installed skills regularly",
		})

		for _, m := range output.SkillsResult.MaliciousMatches {
			output.Vulnerabilities = append(output.Vulnerabilities, models.Vulnerability{
				ID:          uuid.New().String(),
				AssetID:     input.AssetID,
				TaskID:      input.TaskID,
				Title:       fmt.Sprintf("Malicious Skill Detected: %s", m.SkillName),
				Severity:    models.SeverityCritical,
				CVSS:        9.8,
				Description: m.Reason,
				Evidence:    fmt.Sprintf("skill=%s", m.SkillName),
				CheckType:   "skills_check",
				Remediation: fmt.Sprintf("Immediately remove skill '%s' and audit system for compromise indicators", m.SkillName),
			})
		}

		for _, s := range output.SkillsResult.Skills {
			if isSuspicious(s) {
				output.Vulnerabilities = append(output.Vulnerabilities, models.Vulnerability{
					ID:          uuid.New().String(),
					AssetID:     input.AssetID,
					TaskID:      input.TaskID,
					Title:       fmt.Sprintf("Suspicious Skill: %s", s.Name),
					Severity:    models.SeverityHigh,
					CVSS:        7.0,
					Description: fmt.Sprintf("Skill '%s' has suspicious characteristics: %s", s.Name, suspiciousReason(s)),
					Evidence:    fmt.Sprintf("name=%s version=%s author=%s", s.Name, s.Version, s.Author),
					CheckType:   "skills_check",
					Remediation: "Review this skill's code and permissions; remove if not explicitly installed",
				})
			}
		}
	}

	if cfg.EnablePoC {
		output.PoCResults = RunPoCs(input.IP, input.Port, input.AgentType, cfg.Timeout)
		for _, poc := range output.PoCResults {
			if poc.Success {
				output.Vulnerabilities = append(output.Vulnerabilities, models.Vulnerability{
					ID:          uuid.New().String(),
					AssetID:     input.AssetID,
					TaskID:      input.TaskID,
					CVEID:       poc.CVEID,
					Title:       fmt.Sprintf("[PoC] %s", poc.Name),
					Severity:    models.Severity(poc.Severity),
					CVSS:        poc.CVSS,
					Description: poc.Description,
					Evidence:    poc.Evidence,
					CheckType:   "poc_verify",
					Remediation: poc.Remediation,
				})
			}
		}
	}

	output.Vulnerabilities = prioritizeVulnerabilities(output.Vulnerabilities)

	return output
}

func prioritizeVulnerabilities(vulns []models.Vulnerability) []models.Vulnerability {
	if len(vulns) < 2 {
		return vulns
	}

	prioritized := make([]models.Vulnerability, 0, len(vulns))
	seenByCVE := make(map[string]int)

	for _, vuln := range vulns {
		if vuln.CVEID == "" {
			prioritized = append(prioritized, vuln)
			continue
		}

		key := vuln.AssetID + "|" + vuln.CVEID
		if idx, ok := seenByCVE[key]; ok {
			if shouldReplaceVuln(prioritized[idx], vuln) {
				prioritized[idx] = vuln
			}
			continue
		}

		seenByCVE[key] = len(prioritized)
		prioritized = append(prioritized, vuln)
	}

	return prioritized
}

func shouldReplaceVuln(current, candidate models.Vulnerability) bool {
	if current.CheckType == "poc_verify" {
		return false
	}
	if candidate.CheckType == "poc_verify" {
		return true
	}
	return severityRank(candidate.Severity) > severityRank(current.Severity)
}

func severityRank(sev models.Severity) int {
	switch sev {
	case models.SeverityCritical:
		return 5
	case models.SeverityHigh:
		return 4
	case models.SeverityMedium:
		return 3
	case models.SeverityLow:
		return 2
	case models.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func isSuspicious(s SkillInfo) bool {
	name := strings.ToLower(s.Name)
	desc := strings.ToLower(s.Description)
	for _, ind := range getSuspiciousIndicators() {
		if strings.Contains(name, ind) || strings.Contains(desc, ind) {
			return true
		}
	}
	return s.Author == "" && s.Version == ""
}

func suspiciousReason(s SkillInfo) string {
	var reasons []string
	name := strings.ToLower(s.Name)
	desc := strings.ToLower(s.Description)
	for _, ind := range getSuspiciousIndicators() {
		if strings.Contains(name, ind) {
			reasons = append(reasons, fmt.Sprintf("name contains '%s'", ind))
		}
		if strings.Contains(desc, ind) {
			reasons = append(reasons, fmt.Sprintf("description contains '%s'", ind))
		}
	}
	if s.Author == "" && s.Version == "" {
		reasons = append(reasons, "missing author and version metadata")
	}
	if len(reasons) == 0 {
		return "unknown"
	}
	return strings.Join(reasons, "; ")
}

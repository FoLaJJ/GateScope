package l3

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type maliciousSkillRule struct {
	Pattern  string `yaml:"pattern"`
	Reason   string `yaml:"reason"`
	Severity string `yaml:"severity"`
}

type PoCRule struct {
	ID          string  `yaml:"id"`
	Name        string  `yaml:"name"`
	CVEID       string  `yaml:"cve_id"`
	Severity    string  `yaml:"severity"`
	CVSS        float64 `yaml:"cvss"`
	Remediation string  `yaml:"remediation"`
}

type rulesMeta struct {
	UpdatedAt    string `yaml:"updated_at" json:"updated_at"`
	VerifiedAt   string `yaml:"verified_at" json:"verified_at"`
	SourceCutoff string `yaml:"source_cutoff" json:"source_cutoff"`
	Source       string `yaml:"source" json:"source"`
	Notes        string `yaml:"notes" json:"notes"`
}

type cveRulesFile struct {
	Meta rulesMeta  `yaml:"meta"`
	CVEs []CVEEntry `yaml:"cves"`
}

type skillRulesFile struct {
	KnownMalicious       []maliciousSkillRule `yaml:"known_malicious"`
	SuspiciousIndicators []string             `yaml:"suspicious_indicators"`
}

type pocRulesFile struct {
	PoCs []PoCRule `yaml:"pocs"`
}

var defaultKnownMaliciousSkillRules = []maliciousSkillRule{
	{Pattern: "@evilcorp/data-exfil", Reason: "Known data exfiltration skill", Severity: "critical"},
	{Pattern: "@malware/cryptominer", Reason: "Cryptocurrency mining skill", Severity: "critical"},
	{Pattern: "@ghostsocks/proxy", Reason: "GhostSocks C2 proxy skill", Severity: "critical"},
	{Pattern: "@backdoor/reverse-shell", Reason: "Reverse shell backdoor", Severity: "critical"},
	{Pattern: "@fake-official/admin", Reason: "Impersonating official admin skill", Severity: "critical"},
	{Pattern: "openclaw-skill-stealer", Reason: "Credential stealing skill", Severity: "critical"},
	{Pattern: "skill-inject-rce", Reason: "Remote code execution via skill injection", Severity: "critical"},
}

var defaultSuspiciousIndicators = []string{"exec", "shell", "cmd", "eval", "system", "reverse", "backdoor", "inject", "exploit"}

var defaultPoCRules = []PoCRule{
	{ID: "ws_origin_bypass", Name: "WebSocket Origin Bypass", CVEID: "CVE-2026-25253", Severity: "high", CVSS: 8.8, Remediation: "Upgrade to >= 2026.2.25 or enforce Origin header validation"},
	{ID: "path_traversal", Name: "Path Traversal via Skill Paths", CVEID: "CVE-2026-26972", Severity: "high", CVSS: 7.5, Remediation: "Upgrade to >= 2026.3.2"},
	{ID: "ssrf_proxy", Name: "SSRF via Agent Request Proxy", CVEID: "CVE-2026-22234", Severity: "high", CVSS: 7.5, Remediation: "Upgrade to >= 2026.2.14"},
	{ID: "unauth_api", Name: "Unauthenticated API Access", CVEID: "", Severity: "high", CVSS: 8.0, Remediation: "Configure authentication (token_auth or device_auth) for all API endpoints"},
}

var (
	rulesOnce                  sync.Once
	loadedOpenClawCVEs         []CVEEntry
	loadedMaliciousSkillRules  []maliciousSkillRule
	loadedSuspiciousIndicators []string
	loadedPoCRules             []PoCRule
	loadedRulesMeta            rulesMeta
	loadedRuleIssues           []string
)

type RuleCatalogMetadata struct {
	UpdatedAt    string   `json:"updated_at"`
	VerifiedAt   string   `json:"verified_at"`
	SourceCutoff string   `json:"source_cutoff"`
	Source       string   `json:"source"`
	Notes        string   `json:"notes"`
	CVECount     int      `json:"cve_count"`
	PoCCount     int      `json:"poc_count"`
	Consistent   bool     `json:"consistent"`
	Issues       []string `json:"issues"`
}

func getOpenClawCVEs() []CVEEntry {
	rulesOnce.Do(loadRules)
	return loadedOpenClawCVEs
}

func getKnownMaliciousSkillRules() []maliciousSkillRule {
	rulesOnce.Do(loadRules)
	return loadedMaliciousSkillRules
}

func getSuspiciousIndicators() []string {
	rulesOnce.Do(loadRules)
	return loadedSuspiciousIndicators
}

func getPoCRules() []PoCRule {
	rulesOnce.Do(loadRules)
	return loadedPoCRules
}

func GetRuleCatalogMetadata() RuleCatalogMetadata {
	rulesOnce.Do(loadRules)
	issues := make([]string, len(loadedRuleIssues))
	copy(issues, loadedRuleIssues)
	if len(issues) == 0 {
		issues = make([]string, 0)
	}
	return RuleCatalogMetadata{
		UpdatedAt:    loadedRulesMeta.UpdatedAt,
		VerifiedAt:   loadedRulesMeta.VerifiedAt,
		SourceCutoff: loadedRulesMeta.SourceCutoff,
		Source:       loadedRulesMeta.Source,
		Notes:        loadedRulesMeta.Notes,
		CVECount:     len(loadedOpenClawCVEs),
		PoCCount:     len(loadedPoCRules),
		Consistent:   len(issues) == 0,
		Issues:       issues,
	}
}

func getPoCRule(id string) (PoCRule, bool) {
	for _, rule := range getPoCRules() {
		if rule.ID == id {
			return rule, true
		}
	}
	return PoCRule{}, false
}

func hasPoCForCVE(cveID string) bool {
	if strings.TrimSpace(cveID) == "" {
		return false
	}
	for _, rule := range getPoCRules() {
		if rule.CVEID == cveID {
			return true
		}
	}
	return false
}

func loadRules() {
	loadedOpenClawCVEs = append([]CVEEntry(nil), defaultOpenClawCVEs...)
	loadedMaliciousSkillRules = append([]maliciousSkillRule(nil), defaultKnownMaliciousSkillRules...)
	loadedSuspiciousIndicators = append([]string(nil), defaultSuspiciousIndicators...)
	loadedPoCRules = append([]PoCRule(nil), defaultPoCRules...)
	loadedRulesMeta = rulesMeta{}
	loadedRuleIssues = nil

	var cveFile cveRulesFile
	if err := readRulesFile("openclaw-cves.yaml", &cveFile); err == nil && len(cveFile.CVEs) > 0 {
		loadedOpenClawCVEs = cveFile.CVEs
		loadedRulesMeta = cveFile.Meta
	}

	var skillsFile skillRulesFile
	if err := readRulesFile("skills.yaml", &skillsFile); err == nil {
		if len(skillsFile.KnownMalicious) > 0 {
			loadedMaliciousSkillRules = skillsFile.KnownMalicious
		}
		if len(skillsFile.SuspiciousIndicators) > 0 {
			loadedSuspiciousIndicators = skillsFile.SuspiciousIndicators
		}
	}

	var pocsFile pocRulesFile
	if err := readRulesFile("pocs.yaml", &pocsFile); err == nil && len(pocsFile.PoCs) > 0 {
		loadedPoCRules = pocsFile.PoCs
	}

	normalizePoCRules()
}

func normalizePoCRules() {
	for i := range loadedPoCRules {
		rule := &loadedPoCRules[i]
		if strings.TrimSpace(rule.CVEID) == "" {
			continue
		}

		cve, ok := findOpenClawCVE(rule.CVEID)
		if !ok {
			loadedRuleIssues = append(loadedRuleIssues, "PoC rule "+rule.ID+" references missing CVE "+rule.CVEID)
			continue
		}

		rule.Severity = cve.Severity
		rule.CVSS = cve.CVSS
		rule.Remediation = cve.Remediation
	}
}

func findOpenClawCVE(cveID string) (CVEEntry, bool) {
	for _, cve := range loadedOpenClawCVEs {
		if cve.ID == cveID {
			return cve, true
		}
	}
	return CVEEntry{}, false
}

func readRulesFile(filename string, out any) error {
	var lastErr error
	for _, dir := range candidateRuleDirs() {
		path := filepath.Join(dir, filename)
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				lastErr = err
			}
			continue
		}
		return yaml.Unmarshal(data, out)
	}
	if lastErr != nil {
		return lastErr
	}
	return os.ErrNotExist
}

func candidateRuleDirs() []string {
	var dirs []string
	if envDir := os.Getenv("AGENTSCAN_RULES_DIR"); envDir != "" {
		dirs = append(dirs, envDir)
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		dirs = append(dirs,
			filepath.Join(exeDir, "..", "_data", "rules"),
			filepath.Join(exeDir, "..", "configs", "rules"),
		)
	}
	dirs = append(dirs,
		filepath.Join(".", "_data", "rules"),
		filepath.Join(".", "configs", "rules"),
		filepath.Join(string(filepath.Separator), "etc", "agentscan", "rules"),
	)

	seen := map[string]struct{}{}
	unique := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		cleaned := filepath.Clean(dir)
		if strings.TrimSpace(cleaned) == "" {
			continue
		}
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		unique = append(unique, cleaned)
	}
	return unique
}

package l3

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type maliciousSkillRule struct {
	Pattern  string `yaml:"pattern"`
	Reason   string `yaml:"reason"`
	ReasonZH string `yaml:"reason_zh"`
	Severity string `yaml:"severity"`
}

type PoCRule struct {
	ID          string  `yaml:"id"`
	Name        string  `yaml:"name"`
	CVEID       string  `yaml:"cve_id"`
	CNNVDID     string  `yaml:"cnnvd_id"`
	GHSAID      string  `yaml:"ghsa_id"`
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

type ruleIDMapping struct {
	RuleID  string `yaml:"rule_id"`
	CVEID   string `yaml:"cve_id"`
	CNNVDID string `yaml:"cnnvd_id"`
	GHSAID  string `yaml:"ghsa_id"`
}

type idMappingsFile struct {
	Mappings []ruleIDMapping `yaml:"mappings"`
}

type skillRulesFile struct {
	KnownMalicious       []maliciousSkillRule `yaml:"known_malicious"`
	SuspiciousIndicators []string             `yaml:"suspicious_indicators"`
}

type pocRulesFile struct {
	PoCs []PoCRule `yaml:"pocs"`
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
	RuleCount    int      `json:"rule_count"`
	CVECount     int      `json:"cve_count"`
	CNNVDCount   int      `json:"cnnvd_count"`
	GHSACount    int      `json:"ghsa_count"`
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
		RuleCount:    len(loadedOpenClawCVEs),
		CVECount:     countRulesWith(func(rule CVEEntry) bool { return strings.TrimSpace(rule.CVEID) != "" }),
		CNNVDCount:   countRulesWith(func(rule CVEEntry) bool { return strings.TrimSpace(rule.CNNVDID) != "" }),
		GHSACount:    countRulesWith(func(rule CVEEntry) bool { return strings.TrimSpace(rule.GHSAID) != "" }),
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
	loadedOpenClawCVEs = nil
	loadedMaliciousSkillRules = nil
	loadedSuspiciousIndicators = nil
	loadedPoCRules = nil
	loadedRulesMeta = rulesMeta{}
	loadedRuleIssues = nil

	var cveFile cveRulesFile
	if err := readRulesFile("openclaw-cves.yaml", &cveFile); err == nil && len(cveFile.CVEs) > 0 {
		loadedOpenClawCVEs = cveFile.CVEs
		loadedRulesMeta = cveFile.Meta
	} else {
		loadedRuleIssues = append(loadedRuleIssues, "missing or empty rule file openclaw-cves.yaml")
	}
	normalizeOpenClawCVEs()
	applyIDMappings()
	ensureRuleChineseDescriptions()

	var skillsFile skillRulesFile
	if err := readRulesFile("skills.yaml", &skillsFile); err == nil {
		if len(skillsFile.KnownMalicious) > 0 {
			loadedMaliciousSkillRules = skillsFile.KnownMalicious
		}
		if len(skillsFile.SuspiciousIndicators) > 0 {
			loadedSuspiciousIndicators = skillsFile.SuspiciousIndicators
		}
	} else {
		loadedRuleIssues = append(loadedRuleIssues, "missing or empty rule file skills.yaml")
	}

	var pocsFile pocRulesFile
	if err := readRulesFile("pocs.yaml", &pocsFile); err == nil && len(pocsFile.PoCs) > 0 {
		loadedPoCRules = pocsFile.PoCs
	} else {
		loadedRuleIssues = append(loadedRuleIssues, "missing or empty rule file pocs.yaml")
	}

	normalizePoCRules()
	validateRuleIdentifiers()
}

func applyIDMappings() {
	var mappingsFile idMappingsFile
	if err := readRulesFile("openclaw-id-mappings.yaml", &mappingsFile); err != nil {
		return
	}

	seenRuleIDs := make(map[string]struct{}, len(mappingsFile.Mappings))
	for _, mapping := range mappingsFile.Mappings {
		ruleID := strings.TrimSpace(mapping.RuleID)
		if ruleID == "" {
			continue
		}
		if _, ok := seenRuleIDs[ruleID]; ok {
			loadedRuleIssues = append(loadedRuleIssues, "duplicate id mapping for rule "+ruleID)
			continue
		}
		seenRuleIDs[ruleID] = struct{}{}

		applied := false
		for i := range loadedOpenClawCVEs {
			rule := &loadedOpenClawCVEs[i]
			if rule.ID != ruleID {
				continue
			}
			if v := strings.TrimSpace(mapping.CVEID); v != "" {
				rule.CVEID = v
			}
			if v := strings.TrimSpace(mapping.CNNVDID); v != "" {
				rule.CNNVDID = v
			}
			if v := strings.TrimSpace(mapping.GHSAID); v != "" {
				rule.GHSAID = v
			}
			applied = true
			break
		}

		if !applied {
			loadedRuleIssues = append(loadedRuleIssues, "id mapping references missing rule "+ruleID)
		}
	}
}

func validateRuleIdentifiers() {
	seenRuleIDs := make(map[string]struct{}, len(loadedOpenClawCVEs))
	seenCVEs := make(map[string]string, len(loadedOpenClawCVEs))
	seenCNNVDs := make(map[string]string, len(loadedOpenClawCVEs))
	seenGHSAs := make(map[string]string, len(loadedOpenClawCVEs))

	for _, rule := range loadedOpenClawCVEs {
		ruleID := strings.TrimSpace(rule.ID)
		if ruleID != "" {
			if _, ok := seenRuleIDs[ruleID]; ok {
				loadedRuleIssues = append(loadedRuleIssues, "duplicate rule id "+ruleID)
			} else {
				seenRuleIDs[ruleID] = struct{}{}
			}
		}
		recordIdentifierIssue(seenCVEs, strings.TrimSpace(rule.CVEID), ruleID, "cve_id")
		recordIdentifierIssue(seenCNNVDs, strings.TrimSpace(rule.CNNVDID), ruleID, "cnnvd_id")
		recordIdentifierIssue(seenGHSAs, strings.TrimSpace(rule.GHSAID), ruleID, "ghsa_id")
	}
}

func recordIdentifierIssue(seen map[string]string, value, ruleID, field string) {
	if value == "" || ruleID == "" {
		return
	}
	if prevRuleID, ok := seen[value]; ok && prevRuleID != ruleID {
		loadedRuleIssues = append(loadedRuleIssues, field+" "+value+" is mapped to multiple rules: "+prevRuleID+", "+ruleID)
		return
	}
	seen[value] = ruleID
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
		rule.CNNVDID = cve.CNNVDID
		rule.GHSAID = cve.GHSAID
		rule.Remediation = cve.Remediation
	}
}

func normalizeOpenClawCVEs() {
	for i := range loadedOpenClawCVEs {
		rule := &loadedOpenClawCVEs[i]
		if rule.CVEID == "" && strings.HasPrefix(rule.ID, "CVE-") {
			rule.CVEID = rule.ID
		}
		if rule.GHSAID == "" && strings.HasPrefix(rule.ID, "GHSA-") {
			rule.GHSAID = rule.ID
		}
		if rule.ID == "" {
			switch {
			case rule.CVEID != "":
				rule.ID = rule.CVEID
			case rule.GHSAID != "":
				rule.ID = rule.GHSAID
			case rule.CNNVDID != "":
				rule.ID = rule.CNNVDID
			}
		}
	}
}

func findOpenClawCVE(cveID string) (CVEEntry, bool) {
	for _, cve := range loadedOpenClawCVEs {
		if cve.ID == cveID || cve.CVEID == cveID {
			return cve, true
		}
	}
	return CVEEntry{}, false
}

func countRulesWith(match func(rule CVEEntry) bool) int {
	count := 0
	for _, rule := range loadedOpenClawCVEs {
		if match(rule) {
			count++
		}
	}
	return count
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
		filepath.Join("..", "configs", "rules"),
		filepath.Join("..", "..", "configs", "rules"),
		filepath.Join("..", "..", "..", "configs", "rules"),
		filepath.Join(string(filepath.Separator), "etc", "agentscan", "rules"),
	)
	if _, file, _, ok := runtime.Caller(0); ok {
		sourceDir := filepath.Dir(file)
		dirs = append(dirs, filepath.Join(sourceDir, "..", "..", "..", "configs", "rules"))
	}

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

func resetLoadedRulesForTests() {
	rulesOnce = sync.Once{}
	loadedOpenClawCVEs = nil
	loadedMaliciousSkillRules = nil
	loadedSuspiciousIndicators = nil
	loadedPoCRules = nil
	loadedRulesMeta = rulesMeta{}
	loadedRuleIssues = nil
}

package l3

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AutoScan/agentscan/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadRules_AppliesIdentifierMappings(t *testing.T) {
	tmp := t.TempDir()
	rulesDir := filepath.Join(tmp, "rules")
	require.NoError(t, os.MkdirAll(rulesDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "openclaw-cves.yaml"), []byte(`
meta:
  updated_at: "2026-04-03"
cves:
  - id: "GHSA-test-0001"
    title: "mapped rule"
    severity: "high"
    cvss: 8.8
    affected_before: "2026.4.2"
    description: "demo"
    remediation: "upgrade"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "openclaw-id-mappings.yaml"), []byte(`
mappings:
  - rule_id: "GHSA-test-0001"
    cve_id: "CVE-2026-99999"
    cnnvd_id: "CNNVD-202604-999"
    ghsa_id: "GHSA-test-0001"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "skills.yaml"), []byte(`
known_malicious:
  - pattern: "@evil/demo"
    reason: "demo"
    severity: "critical"
suspicious_indicators:
  - exec
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "pocs.yaml"), []byte(`pocs: []`), 0o644))

	prevDir := os.Getenv("AGENTSCAN_RULES_DIR")
	require.NoError(t, os.Setenv("AGENTSCAN_RULES_DIR", rulesDir))
	defer func() {
		if prevDir == "" {
			_ = os.Unsetenv("AGENTSCAN_RULES_DIR")
		} else {
			_ = os.Setenv("AGENTSCAN_RULES_DIR", prevDir)
		}
		resetLoadedRulesForTests()
	}()

	resetLoadedRulesForTests()

	rules := getOpenClawCVEs()
	require.Len(t, rules, 1)
	assert.Equal(t, "CVE-2026-99999", rules[0].CVEID)
	assert.Equal(t, "CNNVD-202604-999", rules[0].CNNVDID)
	assert.Equal(t, "GHSA-test-0001", rules[0].GHSAID)

	meta := GetRuleCatalogMetadata()
	assert.Equal(t, 1, meta.CVECount)
	assert.Equal(t, 1, meta.CNNVDCount)
	assert.Equal(t, 1, meta.GHSACount)
}

func TestLoadRules_FlagsDuplicateIdentifierMappings(t *testing.T) {
	tmp := t.TempDir()
	rulesDir := filepath.Join(tmp, "rules")
	require.NoError(t, os.MkdirAll(rulesDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "openclaw-cves.yaml"), []byte(`
meta:
  updated_at: "2026-04-03"
cves:
  - id: "CVE-2026-10001"
    title: "rule a"
    severity: "high"
    cvss: 8.8
    affected_before: "2026.4.2"
    description: "demo"
    remediation: "upgrade"
  - id: "CVE-2026-10002"
    title: "rule b"
    severity: "medium"
    cvss: 5.3
    affected_before: "2026.4.2"
    description: "demo"
    remediation: "upgrade"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "openclaw-id-mappings.yaml"), []byte(`
mappings:
  - rule_id: "CVE-2026-10001"
    cve_id: "CVE-2026-10001"
    cnnvd_id: "CNNVD-202604-001"
  - rule_id: "CVE-2026-10002"
    cve_id: "CVE-2026-10002"
    cnnvd_id: "CNNVD-202604-001"
  - rule_id: "CVE-2026-10002"
    ghsa_id: "GHSA-test-0002"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "skills.yaml"), []byte("known_malicious: []\nsuspicious_indicators: []\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "pocs.yaml"), []byte("pocs: []\n"), 0o644))

	prevDir := os.Getenv("AGENTSCAN_RULES_DIR")
	require.NoError(t, os.Setenv("AGENTSCAN_RULES_DIR", rulesDir))
	defer func() {
		if prevDir == "" {
			_ = os.Unsetenv("AGENTSCAN_RULES_DIR")
			return
		}
		_ = os.Setenv("AGENTSCAN_RULES_DIR", prevDir)
	}()

	resetLoadedRulesForTests()

	meta := GetRuleCatalogMetadata()
	assert.False(t, meta.Consistent)
	assert.Contains(t, meta.Issues, "duplicate id mapping for rule CVE-2026-10002")
	assert.Contains(t, meta.Issues, "cnnvd_id CNNVD-202604-001 is mapped to multiple rules: CVE-2026-10001, CVE-2026-10002")
}

func TestLocalizeVulnerability_FillsChineseDescriptionFromRule(t *testing.T) {
	tmp := t.TempDir()
	rulesDir := filepath.Join(tmp, "rules")
	require.NoError(t, os.MkdirAll(rulesDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "openclaw-cves.yaml"), []byte(`
meta:
  updated_at: "2026-04-03"
cves:
  - id: "CVE-2026-10001"
    title: "demo rule"
    severity: "high"
    cvss: 8.8
    affected_before: "2026.4.2"
    description: "english demo"
    description_zh: "中文演示描述"
    remediation: "upgrade"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "openclaw-id-mappings.yaml"), []byte("mappings: []\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "skills.yaml"), []byte("known_malicious: []\nsuspicious_indicators: []\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "pocs.yaml"), []byte("pocs: []\n"), 0o644))

	prevDir := os.Getenv("AGENTSCAN_RULES_DIR")
	require.NoError(t, os.Setenv("AGENTSCAN_RULES_DIR", rulesDir))
	defer func() {
		if prevDir == "" {
			_ = os.Unsetenv("AGENTSCAN_RULES_DIR")
			return
		}
		_ = os.Setenv("AGENTSCAN_RULES_DIR", prevDir)
	}()

	resetLoadedRulesForTests()

	vuln := LocalizeVulnerability(models.Vulnerability{
		CVEID:       "CVE-2026-10001",
		Description: "english demo",
	})
	assert.Equal(t, "中文演示描述", vuln.DescriptionZH)
}

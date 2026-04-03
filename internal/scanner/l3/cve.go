package l3

import (
	"fmt"

	"github.com/AutoScan/agentscan/internal/utils/version"
)

type CVEEntry struct {
	ID             string  `yaml:"id"`
	Title          string  `yaml:"title"`
	Severity       string  `yaml:"severity"`
	CVSS           float64 `yaml:"cvss"`
	AffectedBefore string  `yaml:"affected_before"` // versions below this are affected
	Description    string  `yaml:"description"`
	Remediation    string  `yaml:"remediation"`
}

var defaultOpenClawCVEs = []CVEEntry{
	{
		ID: "CVE-2026-25253", Title: "ClawJacked: WebSocket Hijack to RCE",
		Severity: "high", CVSS: 8.8, AffectedBefore: "2026.2.25",
		Description: "Malicious websites can hijack local OpenClaw Gateway via WebSocket without Origin validation, enabling brute-force of auth token and full agent takeover.",
		Remediation: "Upgrade to >= 2026.2.25",
	},
	{
		ID: "CVE-2026-26972", Title: "Path Traversal via crafted skill paths",
		Severity: "high", CVSS: 7.5, AffectedBefore: "2026.3.2",
		Description: "Crafted skill installation path allows reading arbitrary files outside the skills directory.",
		Remediation: "Upgrade to >= 2026.3.2",
	},
	{
		ID: "CVE-2026-28470", Title: "Exec Whitelist Bypass",
		Severity: "critical", CVSS: 9.8, AffectedBefore: "2026.3.2",
		Description: "Bypass of command execution whitelist allows running arbitrary shell commands through the agent.",
		Remediation: "Upgrade to >= 2026.3.2",
	},
	{
		ID: "CVE-2026-26327", Title: "mDNS Gateway Spoofing",
		Severity: "high", CVSS: 7.2, AffectedBefore: "2026.2.25",
		Description: "Unauthenticated mDNS service advertisement allows gateway spoofing on local network.",
		Remediation: "Upgrade to >= 2026.2.25 and disable mDNS in production",
	},
	{
		ID: "CVE-2026-24163", Title: "Remote Code Execution via Skill Installation",
		Severity: "critical", CVSS: 9.8, AffectedBefore: "2026.1.24",
		Description: "Malicious skills can execute arbitrary code during installation without proper sandboxing.",
		Remediation: "Upgrade to >= 2026.1.24",
	},
	{
		ID: "CVE-2026-22234", Title: "Server-Side Request Forgery (SSRF)",
		Severity: "high", CVSS: 7.5, AffectedBefore: "2026.2.14",
		Description: "Agent can be tricked into making requests to internal network resources.",
		Remediation: "Upgrade to >= 2026.2.14",
	},
	{
		ID: "CVE-2026-21980", Title: "Authentication Bypass via Token Prediction",
		Severity: "critical", CVSS: 9.1, AffectedBefore: "2026.2.25",
		Description: "Weak token generation allows prediction and brute-force of authentication tokens.",
		Remediation: "Upgrade to >= 2026.2.25",
	},
	{
		ID: "CVE-2026-32055", Title: "Path Traversal in Workspace Boundary Validation",
		Severity: "high", CVSS: 7.6, AffectedBefore: "2026.2.26",
		Description: "Path traversal vulnerability in workspace boundary validation allows attackers to write files outside the workspace through in-workspace symlinks.",
		Remediation: "Upgrade to >= 2026.2.26",
	},
	{
		ID: "CVE-2026-22172", Title: "Critical Security Vulnerability",
		Severity: "critical", CVSS: 9.4, AffectedBefore: "2026.2.28",
		Description: "Critical vulnerability affecting OpenClaw core functionality, allowing potential system compromise.",
		Remediation: "Upgrade to >= 2026.2.28",
	},
	{
		ID: "CVE-2026-32024", Title: "Symlink Traversal in Avatar Handling",
		Severity: "high", CVSS: 7.5, AffectedBefore: "2026.2.22",
		Description: "Symlink traversal vulnerability in avatar handling allows attackers to read arbitrary files outside the configured workspace boundary.",
		Remediation: "Upgrade to >= 2026.2.22",
	},
	{
		ID: "CVE-2026-31993", Title: "Exec Allowlist Bypass in macOS App",
		Severity: "medium", CVSS: 6.5, AffectedBefore: "2026.2.22",
		Description: "Allowlist parsing mismatch vulnerability in the macOS companion app allows authenticated operators to bypass exec approval checks.",
		Remediation: "Upgrade to >= 2026.2.22",
	},
	{
		ID: "CVE-2026-32062", Title: "Unauthenticated WebSocket DoS",
		Severity: "medium", CVSS: 5.3, AffectedBefore: "2026.2.22",
		Description: "Media-stream WebSocket upgrades accepted before validation, allowing unauthenticated clients to consume server resources.",
		Remediation: "Upgrade to >= 2026.2.22",
	},
}

type CVEMatchResult struct {
	CVE      CVEEntry
	Matched  bool
	Evidence string
}

func MatchCVEs(agentVersion string) []CVEMatchResult {
	var results []CVEMatchResult
	for _, cve := range getOpenClawCVEs() {
		matched := version.LessThan(agentVersion, cve.AffectedBefore)
		results = append(results, CVEMatchResult{
			CVE:      cve,
			Matched:  matched,
			Evidence: buildVersionMatchEvidence(agentVersion, cve),
		})
	}
	return results
}

func buildVersionMatchEvidence(agentVersion string, cve CVEEntry) string {
	evidence := fmt.Sprintf("basis=version_match current_version=%s fixed_version=%s", agentVersion, cve.AffectedBefore)
	if hasPoCForCVE(cve.ID) {
		evidence += " local_poc_rule=available"
	}
	return evidence
}

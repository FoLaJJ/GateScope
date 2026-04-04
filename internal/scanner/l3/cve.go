package l3

import (
	"fmt"

	"github.com/AutoScan/agentscan/internal/utils/version"
)

type CVEEntry struct {
	ID             string  `yaml:"id"`
	CVEID          string  `yaml:"cve_id"`
	CNNVDID        string  `yaml:"cnnvd_id"`
	Title          string  `yaml:"title"`
	Severity       string  `yaml:"severity"`
	CVSS           float64 `yaml:"cvss"`
	AffectedBefore string  `yaml:"affected_before"` // versions below this are affected
	Description    string  `yaml:"description"`
	DescriptionZH  string  `yaml:"description_zh"`
	Remediation    string  `yaml:"remediation"`
}

type CVEMatchResult struct {
	CVE      CVEEntry
	Matched  bool
	Evidence string
}

func MatchCVEs(agentVersion string) []CVEMatchResult {
	var results []CVEMatchResult
	for _, cve := range getOpenClawCVEs() {
		matched := canVersionMatch(agentVersion, cve.AffectedBefore) && version.LessThan(agentVersion, cve.AffectedBefore)
		results = append(results, CVEMatchResult{
			CVE:      cve,
			Matched:  matched,
			Evidence: buildVersionMatchEvidence(agentVersion, cve),
		})
	}
	return results
}

func canVersionMatch(agentVersion, affectedBefore string) bool {
	if _, err := version.Parse(agentVersion); err != nil {
		return false
	}
	if _, err := version.Parse(affectedBefore); err != nil {
		return false
	}
	return true
}

func buildVersionMatchEvidence(agentVersion string, cve CVEEntry) string {
	evidence := fmt.Sprintf("basis=version_match current_version=%s fixed_version=%s", agentVersion, cve.AffectedBefore)
	if cve.CNNVDID != "" {
		evidence += " cnnvd_id=" + cve.CNNVDID
	}
	if hasPoCForCVE(cve.ID) {
		evidence += " local_poc_rule=available"
	}
	return evidence
}

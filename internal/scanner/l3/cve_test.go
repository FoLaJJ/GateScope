package l3

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchCVEs_OldVersion(t *testing.T) {
	results := MatchCVEs("2026.1.20")
	var matched int
	for _, r := range results {
		if r.Matched {
			matched++
		}
	}
	assert.Greater(t, matched, 3, "old version should match multiple CVEs")
}

func TestMatchCVEs_LatestVersion(t *testing.T) {
	results := MatchCVEs("2026.4.2")
	var matched int
	for _, r := range results {
		if r.Matched {
			matched++
		}
	}
	assert.Equal(t, 0, matched, "latest version should match no CVEs")
}

func TestMatchCVEs_PartiallyPatched(t *testing.T) {
	results := MatchCVEs("2026.2.26")
	var matchedCVEs []string
	for _, r := range results {
		if r.Matched {
			matchedCVEs = append(matchedCVEs, r.CVE.ID)
		}
	}
	assert.NotContains(t, matchedCVEs, "CVE-2026-25253", "should be patched in 2026.2.25")
	assert.Contains(t, matchedCVEs, "CVE-2026-26972", "should still be affected (fix is 2026.3.2)")
}

func TestMatchCVEs_GHSAOnlyRuleCarriesIdentifier(t *testing.T) {
	results := MatchCVEs("2026.4.1")
	for _, r := range results {
		if r.CVE.GHSAID == "GHSA-jj6q-rrrf-h66h" {
			assert.True(t, r.Matched)
			assert.Empty(t, r.CVE.CVEID)
			return
		}
	}
	t.Fatalf("GHSA-jj6q-rrrf-h66h rule not found")
}

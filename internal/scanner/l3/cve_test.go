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
	results := MatchCVEs("2026.2.13")
	var matchedCVEs []string
	for _, r := range results {
		if r.Matched {
			matchedCVEs = append(matchedCVEs, r.CVE.ID)
		}
	}
	assert.NotContains(t, matchedCVEs, "CVE-2026-25253", "should be patched in 2026.1.29")
	assert.NotContains(t, matchedCVEs, "CVE-2026-26972", "should be patched in 2026.2.13")
	assert.Contains(t, matchedCVEs, "CVE-2026-26324", "should still be affected (fix is 2026.2.14)")
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

func TestMatchCVEs_UsesVerifiedOpenClawGHSAIdentifiers(t *testing.T) {
	results := MatchCVEs("2026.4.1")
	foundNew := false
	for _, r := range results {
		switch r.CVE.GHSAID {
		case "GHSA-fvx6-pj3r-5q4q":
			assert.True(t, r.Matched)
			foundNew = true
		case "GHSA-2f7j-h9x4-jh34", "GHSA-9jpj-p5w9-9rfc":
			t.Fatalf("stale GHSA identifier still present in rules: %s", r.CVE.GHSAID)
		}
	}
	assert.True(t, foundNew, "verified GHSA-fvx6-pj3r-5q4q rule should be loaded")
}

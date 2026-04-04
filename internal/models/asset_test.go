package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveAssetRisk(t *testing.T) {
	assert.Equal(t, RiskInfo, DeriveAssetRisk("", nil))
	assert.Equal(t, RiskInfo, DeriveAssetRisk("token_auth", nil))
	assert.Equal(t, RiskHigh, DeriveAssetRisk("token_auth", []Severity{SeverityHigh}))
	assert.Equal(t, RiskCritical, DeriveAssetRisk("token_auth", []Severity{SeverityLow, SeverityCritical}))
	assert.Equal(t, RiskLow, DeriveAssetRisk("open", []Severity{SeverityLow}))
}

func TestMaxRiskLevel(t *testing.T) {
	assert.Equal(t, RiskHigh, MaxRiskLevel(RiskLow, RiskHigh, RiskInfo))
	assert.Equal(t, RiskCritical, MaxRiskLevel(RiskMedium, RiskCritical))
}

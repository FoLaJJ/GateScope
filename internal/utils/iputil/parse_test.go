package iputil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTargets(t *testing.T) {
	tests := []struct {
		input string
		count int
	}{
		{"192.168.1.1", 1},
		{"192.168.1.0/30", 2},
		{"192.168.1.1,192.168.1.2", 2},
		{"10.0.0.1-10.0.0.3", 3},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ips, err := ParseTargets(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.count, len(ips))
		})
	}
}

func TestParseTargetsInvalid(t *testing.T) {
	_, err := ParseTargets("not-an-ip")
	assert.Error(t, err)
}

func TestExpandCIDR(t *testing.T) {
	ips, err := ExpandCIDR("192.168.1.0/30")
	require.NoError(t, err)
	assert.Equal(t, 2, len(ips))
	assert.Equal(t, "192.168.1.1", ips[0])
	assert.Equal(t, "192.168.1.2", ips[1])
}

func TestExpandCIDRSingleIP(t *testing.T) {
	ips, err := ExpandCIDR("10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, 1, len(ips))
	assert.Equal(t, "10.0.0.1", ips[0])
}

func TestCountTargets(t *testing.T) {
	assert.Equal(t, 254, CountTargets("192.168.1.0/24"))
	assert.Equal(t, 1, CountTargets("10.0.0.1"))
	assert.Equal(t, 0, CountTargets("invalid"))
}

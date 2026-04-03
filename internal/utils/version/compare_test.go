package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input   string
		major   int
		minor   int
		patch   int
		wantErr bool
	}{
		{"2026.3.13", 2026, 3, 13, false},
		{"v2026.3.13-1", 2026, 3, 13, false},
		{"2026.2.25", 2026, 2, 25, false},
		{"2026.1.24", 2026, 1, 24, false},
		{"1.0", 1, 0, 0, false},
		{"invalid", 0, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v, err := Parse(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.major, v.Major)
			assert.Equal(t, tt.minor, v.Minor)
			assert.Equal(t, tt.patch, v.Patch)
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"2026.3.13", "2026.3.13", 0},
		{"2026.3.13", "2026.2.25", 1},
		{"2026.2.24", "2026.2.25", -1},
		{"2026.1.24", "2026.3.2", -1},
	}
	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			va, _ := Parse(tt.a)
			vb, _ := Parse(tt.b)
			assert.Equal(t, tt.want, Compare(va, vb))
		})
	}
}

func TestLessThan(t *testing.T) {
	assert.True(t, LessThan("2026.2.24", "2026.2.25"))
	assert.False(t, LessThan("2026.2.25", "2026.2.25"))
	assert.False(t, LessThan("2026.3.13", "2026.2.25"))
}

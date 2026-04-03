package version

import (
	"fmt"
	"strconv"
	"strings"
)

type Version struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

func Parse(s string) (Version, error) {
	s = strings.TrimPrefix(s, "v")
	raw := s

	if idx := strings.IndexByte(s, '-'); idx > 0 {
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, '+'); idx > 0 {
		s = s[:idx]
	}

	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return Version{}, fmt.Errorf("invalid version: %s", raw)
	}

	v := Version{Raw: raw}
	var err error
	v.Major, err = strconv.Atoi(parts[0])
	if err != nil {
		return Version{}, fmt.Errorf("invalid major: %s", parts[0])
	}
	v.Minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return Version{}, fmt.Errorf("invalid minor: %s", parts[1])
	}
	if len(parts) > 2 {
		// patch might have trailing non-numeric chars like "13-1"
		patchStr := parts[2]
		if idx := strings.IndexFunc(patchStr, func(r rune) bool { return r < '0' || r > '9' }); idx > 0 {
			patchStr = patchStr[:idx]
		}
		v.Patch, err = strconv.Atoi(patchStr)
		if err != nil {
			return Version{}, fmt.Errorf("invalid patch: %s", parts[2])
		}
	}
	return v, nil
}

// Compare returns -1, 0, or 1
func Compare(a, b Version) int {
	if a.Major != b.Major {
		return cmp(a.Major, b.Major)
	}
	if a.Minor != b.Minor {
		return cmp(a.Minor, b.Minor)
	}
	return cmp(a.Patch, b.Patch)
}

// LessThan returns true if version string a < b
func LessThan(a, b string) bool {
	va, err1 := Parse(a)
	vb, err2 := Parse(b)
	if err1 != nil || err2 != nil {
		return a < b
	}
	return Compare(va, vb) < 0
}

func cmp(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

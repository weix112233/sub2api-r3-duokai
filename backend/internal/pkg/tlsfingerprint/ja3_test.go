package tlsfingerprint

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func parseJA3(raw string) ([5][]uint16, error) {
	var fields [5][]uint16
	parts := strings.Split(raw, ",")
	if len(parts) != len(fields) {
		return fields, fmt.Errorf("JA3 requires five fields")
	}
	for i, part := range parts {
		if part == "" {
			if i == 0 {
				return fields, fmt.Errorf("JA3 version is required")
			}
			continue
		}
		for _, text := range strings.Split(part, "-") {
			n, err := strconv.ParseUint(text, 10, 16)
			if err != nil {
				return fields, fmt.Errorf("invalid JA3 field %d", i)
			}
			fields[i] = append(fields[i], uint16(n))
		}
	}
	if len(fields[0]) != 1 {
		return fields, fmt.Errorf("invalid JA3 version")
	}
	return fields, nil
}

func compareJA3(expected, actual string, shuffled bool) error {
	want, err := parseJA3(expected)
	if err != nil {
		return err
	}
	got, err := parseJA3(actual)
	if err != nil {
		return err
	}
	names := []string{"version", "cipher_suites", "extensions", "curves", "point_formats"}
	for i := range want {
		if i == 2 && shuffled {
			slices.Sort(want[i])
			slices.Sort(got[i])
		}
		if !slices.Equal(want[i], got[i]) {
			return fmt.Errorf("JA3 %s differs: want %v, got %v", names[i], want[i], got[i])
		}
	}
	return nil
}

func assertJA3Fields(t *testing.T, expected, actual string, shuffled bool) {
	t.Helper()
	if err := compareJA3(expected, actual, shuffled); err != nil {
		t.Error(err)
	}
}

func TestJA3Comparison(t *testing.T) {
	const original = "1,2-3,4-5,6,0"
	if err := compareJA3(original, "1,2-3,5-4,6,0", true); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"2,2-3,4-5,6,0", "1,3-2,4-5,6,0", "1,2-3,4-4,6,0", "1,2-3,4-5,7,0", "1,2-3,4-5,6,1"} {
		if compareJA3(original, bad, true) == nil {
			t.Fatal("field mismatch accepted")
		}
	}
	if compareJA3(original, "1,2-3,5-4,6,0", false) == nil {
		t.Fatal("ordered extension mismatch accepted")
	}
	for _, bad := range []string{"", "1,2,3,4", ",,,,", "1-2,3,4,5,6", "1,99999,,,"} {
		if _, err := parseJA3(bad); err == nil {
			t.Fatal("invalid JA3 accepted")
		}
	}
}

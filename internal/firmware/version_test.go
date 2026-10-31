package firmware

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		// The fixture versions (iDRAC8 R730XD, iDRAC9 R240).
		{"2.86.86.86", "7.00.00.182", -1, true},
		{"7.00.00.182", "2.86.86.86", 1, true},
		{"2.19.0", "2.20.0", -1, true},
		{"2.20.0", "2.20.0", 0, true},
		{"25.5.9.0001", "25.5.9.1", 0, true},
		{"23.31.1", "23.0.8", 1, true},
		{"00.24.7A", "00.24.7B", -1, true},
		{"00.24.7A", "00.24.10A", -1, true}, // runs compare numerically
		{"4239A37", "4301A73", -1, true},
		{"E013", "E013", 0, true},
		{"E013", "E9", 1, true},
		{"RS03", "2.5", 0, false}, // letters against a number: no order is guessed
		{"2.5", "RS03", 0, false},
		{"RS03", "RS04", -1, true},
		{"rs03", "RS03", 0, true}, // letters ignore case
		// Padding.
		{"7.10", "7.10.0", 0, true},
		{"7.10", "7.10.0.1", -1, true},
		{"7.10.0.A", "7.10", 0, false}, // a letter segment against a padded zero
		{"10.0", "9.9", 1, true},
		{"99999999999999999999999.1", "99999999999999999999998.9", 1, true}, // no overflow
		// Mixed shapes inside a segment.
		{"1.2a", "1.2", 0, false},
		{"1.A2", "1.2A", 0, false},
		{"1.7A", "1.7A1", 0, false},
		// Invalid input.
		{"", "1", 0, false},
		{"1", "  ", 0, false},
		{"1..2", "1", 0, false},
		{"1.2-beta", "1.2", 0, false},
		{" 2.86 ", "2.86", 0, true},
	}
	for _, c := range cases {
		cmp, ok := CompareVersions(c.a, c.b)
		if cmp != c.cmp || ok != c.ok {
			t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d, %v", c.a, c.b, cmp, ok, c.cmp, c.ok)
		}
	}
}

func TestCompareVersionsIsAntisymmetric(t *testing.T) {
	vs := []string{"2.86.86.86", "7.00.00.182", "25.5.9.0001", "00.24.7A", "4239A37", "E013", "RS03", "23.31.1", "7.10"}
	for _, a := range vs {
		for _, b := range vs {
			x, okx := CompareVersions(a, b)
			y, oky := CompareVersions(b, a)
			if okx != oky || x != -y {
				t.Errorf("%q vs %q: %d,%v and %d,%v", a, b, x, okx, y, oky)
			}
		}
	}
}

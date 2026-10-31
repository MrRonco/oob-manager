package firmware

import "testing"

// FuzzCompareVersions: never panics; comparable pairs are antisymmetric and a version
// equals itself; and the order is transitive across a third version.
func FuzzCompareVersions(f *testing.F) {
	for _, p := range [][3]string{{"2.86.86.86", "2.86.86.87", "3.0"}, {"7A", "10A", "10B"}, {"4239A37", "4301A73", "4301A74"},
		{"1.0", "1.00", "01.0"}, {"", "1", "a"}, {"1..2", "1.2", "9999999999999999999999.1"}} {
		f.Add(p[0], p[1], p[2])
	}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		ab, okAB := CompareVersions(a, b)
		ba, okBA := CompareVersions(b, a)
		if okAB != okBA || (okAB && ab != -ba) {
			t.Fatalf("not antisymmetric: %q %q -> %d,%v / %d,%v", a, b, ab, okAB, ba, okBA)
		}
		if aa, ok := CompareVersions(a, a); ok && aa != 0 {
			t.Fatalf("%q != itself", a)
		}
		bc, okBC := CompareVersions(b, c)
		ac, okAC := CompareVersions(a, c)
		if okAB && okBC && okAC && ab <= 0 && bc <= 0 && ac > 0 {
			t.Fatalf("not transitive: %q <= %q <= %q but %q > %q", a, b, c, a, c)
		}
	})
}

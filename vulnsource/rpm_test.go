package vulnsource

import "testing"

// rpmvercmp, from rpm's own test vectors (tests/rpmvercmp.at): segments are
// digit or letter runs; digits beat letters; leading zeros do not count;
// "~" sorts before everything, even the end; "^" sorts after the end but
// before any further segment.
func TestRPMVerCmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0.1", "2.0.1", 0},
		{"2.0", "2.0.1", -1},
		{"2.0.1a", "2.0.1", 1},
		{"5.5p1", "5.5p2", -1},
		{"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10.1", -1},
		{"xyz.4", "8", -1},
		{"5.5p1", "5.5.p1", 0},
		{"10b2", "10a1", 1},
		{"1.0010", "1.9", 1},
		{"1.05", "1.5", 0},
		{"1.0", "1", 1},
		{"2_0", "2_0", 0},
		{"2.0", "2_0", 0},
		{"a", "a", 0},
		{"a+", "a_", 0},
		{"+", "_", 0},
		{"1.0~rc1", "1.0~rc1", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1~git123", "1.0~rc1", -1},
		{"1.0^", "1.0", 1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.01", -1},
		{"1.0^20160101", "1.0.1", -1},
		{"1.0~rc1^git1", "1.0~rc1", 1},
	}
	for _, c := range cases {
		if got := rpmvercmp(c.a, c.b); got != c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := rpmvercmp(c.b, c.a); got != -c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

// An RPM EVR compares epoch, then version, then release; a missing epoch is
// 0. OSV's AlmaLinux and Rocky advisories are written this way
// ("1:3.0.1-41.el9_0").
func TestRPMOrderSelectsTheFix(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1:3.0.1-41.el9_0", "1:3.0.1-43.el9_0", -1},
		{"1:3.0.1-41.el9_0", "3.5.0-1.el9", 1}, // epoch dominates
		{"0:3.0.1-1", "3.0.1-1", 0},
		{"3.0.7-27.el9", "3.0.7-6.el9", 1},
		{"2.34-100.el9_4.2", "2.34-100.el9_4.10", -1},
	}
	for _, c := range cases {
		got, ok := compareRPM(c.a, c.b)
		if !ok || sign(got) != c.want {
			t.Errorf("compareRPM(%q, %q) = %d, %v; want %d", c.a, c.b, got, ok, c.want)
		}
	}
	iv := Interval{Introduced: "0", Fixed: "1:3.0.1-41.el9_0"}
	if !iv.coversIn("AlmaLinux:9", "1:3.0.1-23.el9_0") || iv.coversIn("Rocky Linux:9", "1:3.0.7-24.el9") {
		t.Error("RPM interval did not bound with EVR order (semver puts -23 before -41 only by luck; 3.0.7 vs 3.0.1 by epoch)")
	}
	if c := compareIn("AlmaLinux:9", "2.34-100.el9_4.10", "2.34-100.el9_4.2"); c <= 0 {
		t.Errorf("AlmaLinux compareIn put el9_4.10 before el9_4.2 (%d)", c)
	}
}

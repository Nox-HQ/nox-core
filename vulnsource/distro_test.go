package vulnsource

import "testing"

// Debian's ordering (dpkg's verrevcmp): the epoch dominates; within upstream
// and revision, "~" sorts before everything including the end of the string,
// letters before non-letters, and digit runs compare as numbers. A missing
// revision is "0".
func TestCompareDpkg(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1:0.1", "2.0", 1},        // epoch dominates
		{"1.0~rc1", "1.0", -1},     // tilde before the end
		{"1.0~rc1", "1.0~rc2", -1}, //
		{"1.0~~", "1.0~", -1},      //
		{"1.0a", "1.0+", -1},       // letters before non-letters
		{"1.10", "1.9", 1},         // numeric
		{"1.0", "1.0-0", 0},        // missing revision is 0
		{"3.0.15-1~deb12u1", "3.0.15-1", -1},
		{"2.36-9+deb12u7", "2.36-9+deb12u10", -1},
		{"1:2.39.2-1.1", "1:2.39.5-0+deb12u1", -1},
	}
	for _, c := range cases {
		got, ok := compareDpkg(c.a, c.b)
		if !ok || sign(got) != c.want {
			t.Errorf("compareDpkg(%q, %q) = %d, %v; want %d", c.a, c.b, got, ok, c.want)
		}
		if back, _ := compareDpkg(c.b, c.a); sign(back) != -c.want {
			t.Errorf("compareDpkg(%q, %q) is not antisymmetric", c.b, c.a)
		}
	}
}

// Alpine's ordering (apk-tools): numbers compare as numbers, a trailing
// letter sorts after none, the pre-release suffixes _alpha < _beta < _pre <
// _rc sort before no suffix and the post-release ones (_p and friends) after,
// and -rN revisions compare as numbers.
func TestCompareAPK(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.2.10", "1.2.9", 1},
		{"1.0", "1.0a", -1},
		{"1.0_alpha", "1.0_beta", -1},
		{"1.0_beta", "1.0_pre", -1},
		{"1.0_pre", "1.0_rc", -1},
		{"1.0_rc1", "1.0", -1},
		{"1.0", "1.0_p1", -1},
		{"1.0_rc1", "1.0_rc2", -1},
		{"1.0-r1", "1.0-r2", -1},
		{"1.0", "1.0-r0", 0},
		{"3.0.15-r1", "3.5.1-r0", -1},
		{"3.5.1-r0", "3.5.1-r10", -1},
		{"1.36.1-r7", "1.36.1-r29", -1},
	}
	for _, c := range cases {
		got, ok := compareAPK(c.a, c.b)
		if !ok || sign(got) != c.want {
			t.Errorf("compareAPK(%q, %q) = %d, %v; want %d", c.a, c.b, got, ok, c.want)
		}
		if back, _ := compareAPK(c.b, c.a); sign(back) != -c.want {
			t.Errorf("compareAPK(%q, %q) is not antisymmetric", c.b, c.a)
		}
	}
	if _, ok := compareAPK("not a version", "1.0"); ok {
		t.Error("an unreadable apk version was compared")
	}
}

// The distribution's ordering decides which advisory interval covers an
// installed version and which fix is the smallest: plain semver ordering puts
// 1.0-r10 before 1.0-r9 and 1.0~rc1 after 1.0.
func TestDistroOrderingSelectsTheFix(t *testing.T) {
	iv := Interval{Introduced: "0", Fixed: "3.0.15-r1"}
	if !iv.coversIn("Alpine:v3.20", "3.0.15-r0") || iv.coversIn("Alpine:v3.20", "3.0.15-r1") {
		t.Error("Alpine interval did not bound on -rN")
	}
	deb := Interval{Introduced: "0", Fixed: "3.0.15-1~deb12u1"}
	if !deb.coversIn("Debian:12", "3.0.11-1~deb12u2") || deb.coversIn("Debian:12", "3.0.15-1~deb12u1") {
		t.Error("Debian interval did not bound with dpkg ordering")
	}
	// A backport built before the fixed upload is still vulnerable: "~" sorts
	// before the end, where semver's prerelease rule puts it after.
	tilde := Interval{Introduced: "0", Fixed: "3.0.15-1"}
	if !tilde.coversIn("Debian:12", "3.0.15-1~deb12u1") {
		t.Error("Debian interval did not cover a ~ backport below the fix")
	}
	if c := compareIn("Alpine:v3.20", "1.0-r10", "1.0-r9"); c <= 0 {
		t.Errorf("Alpine compareIn put r10 before r9 (%d)", c)
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

package vulnsource

import "testing"

func TestCompareVersionsUsesEverySegment(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.6.0.7", "6.6.0.3", 1},
		{"6.6.0.3", "6.6.0.7", -1},
		{"4.8.0.83", "4.8.0.9", 1},
		{"2.4.8.13", "2.4.8.13", 0},
		{"1.2", "1.2.0", 0},
		{"1.2", "1.2.0.0", 0},
		{"1.2", "1.2.0.1", -1},
		{"1.2.3.4.5", "1.2.3.4.4", 1},
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0.1-rc1", "1.0.0.1", -1},
		{"v2.0.0", "2.0.0", 0},
		{"1.10.0", "1.9.0", 1},
		{"1.2.3+build", "1.2.3", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIntervalCoversFourSegmentVersions(t *testing.T) {
	iv := Interval{Introduced: "6.6.0.0", Fixed: "6.6.0.5"}
	if !iv.Covers("6.6.0.3") || iv.Covers("6.6.0.7") || iv.Covers("6.6.0.5") {
		t.Error("a four-segment range must bound on the fourth segment")
	}
}

package vulnsource

import (
	"encoding/json"
	"os"
	"testing"
)

// The cases below are OSV's own (osv/ecosystems/maven_test.py, themselves
// ported from Maven's ComparableVersionTest). The mirror answers in OSV's
// place, so where Maven and the specification disagree it is OSV's reading
// that counts.

func TestMavenNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"1.0.0":              "1",
		"1.ga":               "1",
		"1.final":            "1",
		"1.0":                "1",
		"1.":                 "1",
		"1-":                 "1",
		"1.0.0-foo.0.0":      "1-foo",
		"1.0.0-0.0.0":        "1",
		"1-1.foo-bar1baz-.1": "1-1.foo-bar-1-baz-0.1",
		"1cr":                "1-rc",
		"1a":                 "1-a",
		"1a1":                "1-alpha-1",
		"1b1":                "1-beta-1",
		"1c1":                "1-c-1",
		"1m1":                "1-milestone-1",
		"1-ga-1":             "1-1",
	} {
		if got := parseMaven(in).String(); got != want {
			t.Errorf("parseMaven(%q) = %q, want %q", in, got, want)
		}
	}
}

// checkMavenOrder asserts every earlier version sorts strictly below every
// later one, in both directions.
func checkMavenOrder(t *testing.T, versions ...string) {
	t.Helper()
	for i := range versions {
		for j := i + 1; j < len(versions); j++ {
			if c := compareMaven(versions[i], versions[j]); c >= 0 {
				t.Errorf("compareMaven(%q, %q) = %d, want < 0", versions[i], versions[j], c)
			}
			if c := compareMaven(versions[j], versions[i]); c <= 0 {
				t.Errorf("compareMaven(%q, %q) = %d, want > 0", versions[j], versions[i], c)
			}
		}
	}
}

func checkMavenEqual(t *testing.T, versions ...string) {
	t.Helper()
	for i := range versions {
		for j := range versions {
			if c := compareMaven(versions[i], versions[j]); c != 0 {
				t.Errorf("compareMaven(%q, %q) = %d, want 0", versions[i], versions[j], c)
			}
		}
	}
}

func TestMavenOrderQualifiers(t *testing.T) {
	checkMavenOrder(t,
		"1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123",
		"1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp",
		"1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot", "1-1",
		"1-2", "1-123")
}

func TestMavenOrderNumbers(t *testing.T) {
	checkMavenOrder(t,
		"2.0", "2-1", "2.0.a", "2.0.0.a", "2.0.2", "2.0.123", "2.1.0", "2.1-a",
		"2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11",
		"11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m")
}

func TestMavenOrderPairs(t *testing.T) {
	for _, p := range [][2]string{
		{"1", "2"}, {"1.5", "2"}, {"1", "2.5"}, {"1.0", "1.1"}, {"1.1", "1.2"},
		{"1.0.0", "1.1"}, {"1.0.1", "1.1"}, {"1.1", "1.2.0"},
		{"1.0-alpha-1", "1.0"}, {"1.0-alpha-1", "1.0-alpha-2"},
		{"1.0-alpha-1", "1.0-beta-1"}, {"1.0-beta-1", "1.0-SNAPSHOT"},
		{"1.0-SNAPSHOT", "1.0"}, {"1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"},
		{"1.0", "1.0-1"}, {"1.0-1", "1.0-2"}, {"1.0.0", "1.0-1"},
		{"2.0-1", "2.0.1"}, {"2.0.1-klm", "2.0.1-lmn"}, {"2.0.1", "2.0.1-xyz"},
		{"2.0.1", "2.0.1-123"}, {"2.0.1-xyz", "2.0.1-123"},
		{"0-alpha-alpha", "0-alpha"}, {"alpha", "0.0"},
		// OSV also orders "0" below "alpha-alpha-…", but in its generic sort key
		// for an introduced "0", which coversIn already treats as no bound.
		{"0.0", "1"},
		{"0.0.0-2021-05-17T01-01-51-5ec03a8b", "20.0.0"},
		{"1.2.0", "1.10.0"},
		// MNG-5568 and MNG-6572: no ordering cycle, and numbers wider than
		// any machine integer still compare by value.
		{"6.1.0rc3", "6.1.0"}, {"6.1.0rc3", "6.1H.5-beta"}, {"6.1.0", "6.1H.5-beta"},
		{"20190126.230843", "1234567890.12345"},
		{"1234567890.12345", "123456789012345.1H.5-beta"},
		{"123456789012345.1H.5-beta", "12345678901234567890.1H.5-beta"},
	} {
		checkMavenOrder(t, p[0], p[1])
	}
}

func TestMavenEqual(t *testing.T) {
	for _, set := range [][]string{
		{"1", "1.0", "1.0.0", "1-0", "1.0-0"},
		{"1a", "1-a", "1.0-a", "1.0.0-a", "1.0a", "1.0.0a"},
		{"1x", "1-x", "1.0-x", "1.0.0-x", "1.0x", "1.0.0x", "1X"},
		{"1", "1ga", "1release", "1final", "1Ga", "1GA", "1RELEASE", "1RELeaSE", "1Final", "1FINAL"},
		{"1cr", "1rc", "1Cr", "1Rc", "1cR", "1rC"},
		{"1a1", "1-alpha-1"}, {"1b2", "1-beta-2"},
		{"1m3", "1-milestone-3", "1Milestone3", "1MileStone3", "1MILESTONE3"},
		{"1", "01", "001"}, {"1.1", "1.01", "1.001"}, {"1-1", "1-01", "1-001"},
		{"0.0.0", "0.0", "0-0", "0.0.0-0.0.0", "0-final-ga"},
	} {
		checkMavenEqual(t, set...)
	}
}

// A qualifier Maven does not know sorts above the release it qualifies, so
// "33.7.2-jre" is the 33.7.2 release, not a prerelease of it. The generic
// comparator read "-jre" as a SemVer prerelease and reported every Guava
// "-jre"/"-android" build at a fix version as still affected (GHSA-xxph-c9ww-hj94,
// fixed in 33.7.2), where OSV says it is not.
func TestDecideMavenQualifiedRelease(t *testing.T) {
	b, err := os.ReadFile("testdata/GHSA-xxph-c9ww-hj94.json")
	if err != nil {
		t.Fatal(err)
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	const pkg = "com.google.guava:guava"
	cases := map[string]Verdict{
		"3.0":             VerdictNotAffected, // below introduced 4.0
		"4.0":             VerdictAffected,
		"33.7.1-jre":      VerdictAffected,
		"33.7.1-android":  VerdictAffected,
		"33.7.2-rc1":      VerdictAffected, // a release candidate precedes the fix
		"33.7.2-SNAPSHOT": VerdictAffected,
		"33.7.2":          VerdictNotAffected,
		"33.7.2-jre":      VerdictNotAffected,
		"33.7.2-android":  VerdictNotAffected,
		"33.8.0-jre":      VerdictNotAffected,
	}
	for v, want := range cases {
		if got := r.Decide(pkg, "Maven", v); got != want {
			t.Errorf("Decide(%s) = %v, want %v", v, got, want)
		}
		if got := r.Affects(pkg, "Maven", v); got != (want == VerdictAffected) {
			t.Errorf("Affects(%s) = %v, want %v", v, got, want == VerdictAffected)
		}
	}
	if got := r.FixedVersion(pkg, "Maven", "33.7.1-jre"); got != "33.7.2" {
		t.Errorf("FixedVersion(33.7.1-jre) = %q, want 33.7.2", got)
	}
}

// Spring published releases as "5.3.0.RELEASE". The generic comparator could
// not order a lettered segment, so such a version was undecidable (a live OSV
// round trip) at best; under Maven's rule ".RELEASE" is the release itself.
func TestDecideMavenReleaseSuffix(t *testing.T) {
	r := Record{ID: "X", Affected: []Affected{{
		Package: Package{Name: "org.springframework:spring-core", Ecosystem: "Maven"},
		Ranges:  []Range{rng("ECOSYSTEM", Event{Introduced: "0"}, Event{Fixed: "4.3.30.RELEASE"})},
	}}}
	for v, want := range map[string]Verdict{
		"4.3.29.RELEASE": VerdictAffected,
		"4.3.30":         VerdictNotAffected,
		"4.3.30.RELEASE": VerdictNotAffected,
		"5.0.0.RELEASE":  VerdictNotAffected,
	} {
		if got := r.Decide("org.springframework:spring-core", "Maven", v); got != want {
			t.Errorf("Decide(%s) = %v, want %v", v, got, want)
		}
	}
}

// A version that does not start with a number has no place in a release line
// the mirror can vouch for; OSV can order it, so it is left to OSV.
func TestDecideMavenNonNumericIsUndecidable(t *testing.T) {
	r := Record{ID: "X", Affected: []Affected{{
		Package: Package{Name: "g:a", Ecosystem: "Maven"},
		Ranges:  []Range{rng("ECOSYSTEM", Event{Introduced: "0"}, Event{Fixed: "2.0"})},
	}}}
	if got := r.Decide("g:a", "Maven", "latest"); got != VerdictUndecidable {
		t.Errorf("Decide(latest) = %v, want undecidable", got)
	}
}

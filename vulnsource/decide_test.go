package vulnsource

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func affected(vers []string, ranges ...Range) Record {
	return Record{ID: "X", Affected: []Affected{{
		Package:  Package{Name: "pkg", Ecosystem: "Hex"},
		Versions: vers,
		Ranges:   ranges,
	}}}
}

func rng(typ string, ev ...Event) Range { return Range{Type: typ, Events: ev} }

var (
	gitRange    = rng("GIT", Event{Introduced: "05ab4f438bf0cd0fdfb279d912bbe0d2c3620e02"}, Event{Fixed: "a3253fb4fc7145aeb403537af1c24d3a8d51ffb1"})
	semverRange = rng("SEMVER", Event{Introduced: "0"}, Event{Fixed: "3.0.0"})
)

func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		rec  Record
		ver  string
		want Verdict
	}{
		{"listed version", affected([]string{"2.9.0"}, gitRange), "2.9.0", VerdictAffected},
		{"listed with v prefix", affected([]string{"v2.9.0"}), "2.9.0", VerdictAffected},
		{"git range with list, version absent: the range may know more", affected([]string{"2.9.0"}, gitRange), "1.0.0", VerdictUndecidable},
		{"git range with list, version listed", affected([]string{"2.9.0"}, gitRange), "2.9.0", VerdictAffected},
		{"git only, no list", affected(nil, gitRange), "2.9.0", VerdictUndecidable},
		{"no ranges, no list", affected(nil), "2.9.0", VerdictUndecidable},
		{"semver covers", affected(nil, semverRange), "2.9.0", VerdictAffected},
		{"semver fixed", affected(nil, semverRange), "3.0.0", VerdictNotAffected},
		{"semver covers beside git", affected(nil, gitRange, semverRange), "2.9.0", VerdictAffected},
		{"semver misses beside git", affected(nil, gitRange, semverRange), "3.1.0", VerdictUndecidable},
		{"unknown range type", affected(nil, rng("WEIRD", Event{Introduced: "0"})), "1.0.0", VerdictUndecidable},
		{"list plus semver miss", affected([]string{"9.9.9"}, semverRange), "5.0.0", VerdictNotAffected},
	}
	for _, c := range cases {
		if got := c.rec.Decide("pkg", "Hex", c.ver); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDecideWithdrawnAndOtherPackages(t *testing.T) {
	r := affected([]string{"1.0.0"})
	r.Withdrawn = "2024-01-01T00:00:00Z"
	if r.Decide("pkg", "Hex", "1.0.0") != VerdictNotAffected {
		t.Error("withdrawn advisory must affect nothing")
	}
	other := affected(nil, gitRange)
	if other.Decide("elsewhere", "Hex", "1.0.0") != VerdictNotAffected {
		t.Error("an entry for another package says nothing about this one")
	}
	if other.Decide("pkg", "npm", "1.0.0") != VerdictNotAffected {
		t.Error("an entry for another ecosystem says nothing about this one")
	}
}

func TestAffectedVersionsRoundTrip(t *testing.T) {
	in := `{"id":"X","affected":[{"package":{"name":"p","ecosystem":"Hex"},"versions":["1.0.0","1.1.0"]}]}`
	var r Record
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Affected[0].Versions) != 2 {
		t.Fatalf("versions not decoded: %+v", r.Affected[0])
	}
	b, _ := json.Marshal(r)
	var back Record
	_ = json.Unmarshal(b, &back)
	if len(back.Affected[0].Versions) != 2 {
		t.Errorf("versions lost on encode: %s", b)
	}
	var plain Record
	_ = json.Unmarshal([]byte(`{"id":"X","affected":[{"package":{"name":"p","ecosystem":"Hex"}}]}`), &plain)
	if b, _ := json.Marshal(plain); strings.Contains(string(b), `"versions"`) {
		t.Errorf("empty versions must be omitted: %s", b)
	}
}

func TestOrderedIntervalsSkipsGitHashes(t *testing.T) {
	r := affected([]string{"1.0.0", "1.0.0", "2.0.0"}, gitRange, semverRange)
	if got := r.AffectedIntervals("pkg", "Hex"); len(got) != 2 {
		t.Fatalf("AffectedIntervals folds every range type: %v", got)
	}
	got := r.OrderedIntervals("pkg", "Hex")
	if len(got) != 1 || got[0].Fixed != "3.0.0" {
		t.Errorf("OrderedIntervals = %v, want only the SEMVER interval", got)
	}
	if v := r.ListedVersions("pkg", "Hex"); len(v) != 2 || v[0] != "1.0.0" || v[1] != "2.0.0" {
		t.Errorf("ListedVersions = %v", v)
	}
	if v := r.ListedVersions("other", "Hex"); len(v) != 0 {
		t.Errorf("ListedVersions for another package = %v", v)
	}
}

// The two hackney advisories as api.osv.dev serves them (EEF-CVE-2026-112880 and
// -113440): a package entry with a SEMVER range and a version list, and a
// separate package-less entry holding the GIT range. 2.0.0 and 3.0.0 are
// affected; the decision must not depend on the GIT entry.
func TestDecideRealHackneyRecords(t *testing.T) {
	for _, id := range []string{"EEF-CVE-2026-112880", "EEF-CVE-2026-113440"} {
		b, err := os.ReadFile("testdata/" + id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{"2.0.0", "3.0.0", "4.8.7"} {
			if got := r.Decide("hackney", "Hex", v); got != VerdictAffected {
				t.Errorf("%s hackney %s = %v, want affected", id, v, got)
			}
		}
		if got := r.Decide("hackney", "Hex", "4.9.0"); got != VerdictNotAffected {
			t.Errorf("%s hackney 4.9.0 (the fixed version) = %v", id, got)
		}
	}
}

func listed(eco string, vers ...string) Record {
	return Record{ID: "X", Affected: []Affected{{
		Package:  Package{Name: "pkg", Ecosystem: eco},
		Versions: vers,
	}}}
}

// PYSEC-2013-19 and PYSEC-2022-304 as api.osv.dev serves them (details and
// references trimmed). django 1.4.0 is affected through the explicit versions
// list, which spells it "1.4"; neither ECOSYSTEM range covers it. OSV matches
// them because PyPI versions compare under PEP 440, where 1.4 == 1.4.0.
func TestDecideRealDjangoRecords(t *testing.T) {
	for _, id := range []string{"PYSEC-2013-19", "PYSEC-2022-304"} {
		b, err := os.ReadFile("testdata/" + id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		if got := r.Decide("django", "PyPI", "1.4.0"); got != VerdictAffected {
			t.Errorf("%s django 1.4.0 = %v, want affected", id, got)
		}
		if got := r.Decide("django", "PyPI", "1.4"); got != VerdictAffected {
			t.Errorf("%s django 1.4 = %v, want affected", id, got)
		}
		if got := r.Decide("django", "PyPI", "99.0"); got == VerdictAffected {
			t.Errorf("%s django 99.0 must not be affected", id)
		}
	}
}

func TestDecideListedVersionEquality(t *testing.T) {
	cases := []struct {
		name string
		eco  string
		list []string
		ver  string
		want Verdict
	}{
		// PyPI: PEP 440 equality is affected.
		{"pypi trailing zeros", "PyPI", []string{"1.4"}, "1.4.0", VerdictAffected},
		{"pypi trailing zeros reverse", "PyPI", []string{"1.4.0"}, "1.4", VerdictAffected},
		{"pypi four segments", "PyPI", []string{"1.4"}, "1.4.0.0", VerdictAffected},
		{"pypi v prefix", "PyPI", []string{"1.4"}, "v1.4.0", VerdictAffected},
		{"pypi case", "PyPI", []string{"1.0RC1"}, "1.0rc1", VerdictAffected},
		{"pypi rc dot", "PyPI", []string{"1.0rc1"}, "1.0.rc1", VerdictAffected},
		{"pypi rc dash", "PyPI", []string{"1.0-rc1"}, "1.0rc1", VerdictAffected},
		{"pypi c is rc", "PyPI", []string{"1.0c1"}, "1.0rc1", VerdictAffected},
		{"pypi alpha is a", "PyPI", []string{"1.0alpha2"}, "1.0a2", VerdictAffected},
		{"pypi implicit pre number", "PyPI", []string{"1.0a"}, "1.0a0", VerdictAffected},
		{"pypi post dot", "PyPI", []string{"1.0.post1"}, "1.0post1", VerdictAffected},
		{"pypi implicit post", "PyPI", []string{"1.0-1"}, "1.0.post1", VerdictAffected},
		{"pypi rev is post", "PyPI", []string{"1.0-rev1"}, "1.0.post1", VerdictAffected},
		{"pypi dev dot", "PyPI", []string{"1.0.dev3"}, "1.0dev3", VerdictAffected},
		{"pypi release then zeros then pre", "PyPI", []string{"1.0rc1"}, "1.0.0rc1", VerdictAffected},
		{"pypi epoch equal", "PyPI", []string{"1!2.0"}, "1!2.0.0", VerdictAffected},
		{"pypi local separators", "PyPI", []string{"1.0+ubuntu-1"}, "1.0+ubuntu.1", VerdictAffected},
		{"pypi exact unchanged", "PyPI", []string{"1.4.0"}, "1.4.0", VerdictAffected},

		// PyPI: distinct versions stay distinct.
		{"pypi epoch mismatch listed", "PyPI", []string{"1!2.0"}, "2.0", VerdictNotAffected},
		{"pypi epoch mismatch queried", "PyPI", []string{"2.0"}, "1!2.0", VerdictNotAffected},
		{"pypi post is not the release", "PyPI", []string{"1.0.post1"}, "1.0", VerdictNotAffected},
		{"pypi pre is not the release", "PyPI", []string{"1.0rc1"}, "1.0", VerdictNotAffected},
		{"pypi rc1 is not rc2", "PyPI", []string{"1.0rc1"}, "1.0rc2", VerdictNotAffected},
		{"pypi dev is not the release", "PyPI", []string{"1.0.dev1"}, "1.0", VerdictNotAffected},
		{"pypi absent from list", "PyPI", []string{"1.4"}, "1.5.0", VerdictNotAffected},

		// Not confidently normalizable and numerically equal: refuse to decide.
		{"pypi exotic spelling", "PyPI", []string{"1.4.0.weird"}, "1.4", VerdictUndecidable},
		{"pypi exotic query", "PyPI", []string{"1.4"}, "1.4.0.weird", VerdictUndecidable},

		// Other ecosystems: "1.4" and "1.4.0" are distinct there, but numerically
		// equal, so the mirror must not claim they differ.
		{"npm list 1.4 vs 1.4.0", "npm", []string{"1.4"}, "1.4.0", VerdictUndecidable},
		{"npm list 1.4.0 vs 1.4", "npm", []string{"1.4.0"}, "1.4", VerdictUndecidable},
		{"go list vs v-prefixed zeros", "Go", []string{"v1.4"}, "1.4.0", VerdictUndecidable},
		{"crates", "crates.io", []string{"1.4"}, "1.4.0", VerdictUndecidable},
		{"npm exact unchanged", "npm", []string{"1.4.0"}, "1.4.0", VerdictAffected},
		{"npm v prefix unchanged", "npm", []string{"v1.4.0"}, "1.4.0", VerdictAffected},
		{"npm absent from list", "npm", []string{"1.4"}, "1.5.0", VerdictNotAffected},
		{"npm distinct prerelease", "npm", []string{"1.4.0-beta"}, "1.4.0", VerdictNotAffected},
	}
	for _, c := range cases {
		r := listed(c.eco, c.list...)
		if got := r.Decide("pkg", c.eco, c.ver); got != c.want {
			t.Errorf("%s: list %v ver %q: got %v, want %v", c.name, c.list, c.ver, got, c.want)
		}
	}
}

// A near-equal list entry must not mask an ordered range that does cover the
// version, and must not turn an otherwise-decided miss into Undecidable when
// the list holds only genuinely different versions.
func TestDecideNearListEntryBesideRanges(t *testing.T) {
	r := listed("npm", "1.4")
	r.Affected[0].Ranges = []Range{rng("SEMVER", Event{Introduced: "0"}, Event{Fixed: "3.0.0"})}
	if got := r.Decide("pkg", "npm", "1.4.0"); got != VerdictAffected {
		t.Errorf("range covers: got %v, want affected", got)
	}
	if got := r.Decide("pkg", "npm", "5.0.0"); got != VerdictNotAffected {
		t.Errorf("outside everything: got %v, want not-affected", got)
	}
}

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

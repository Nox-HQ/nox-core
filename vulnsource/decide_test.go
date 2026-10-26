package vulnsource

import (
	"encoding/json"
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
		{"git range with list, version absent: the list is complete", affected([]string{"2.9.0"}, gitRange), "1.0.0", NotAffected},
		{"git only, no list", affected(nil, gitRange), "2.9.0", Undecidable},
		{"no ranges, no list", affected(nil), "2.9.0", Undecidable},
		{"semver covers", affected(nil, semverRange), "2.9.0", VerdictAffected},
		{"semver fixed", affected(nil, semverRange), "3.0.0", NotAffected},
		{"semver covers beside git", affected(nil, gitRange, semverRange), "2.9.0", VerdictAffected},
		{"semver misses beside git", affected(nil, gitRange, semverRange), "3.1.0", Undecidable},
		{"unknown range type", affected(nil, rng("WEIRD", Event{Introduced: "0"})), "1.0.0", Undecidable},
		{"list plus semver miss", affected([]string{"9.9.9"}, semverRange), "5.0.0", NotAffected},
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
	if r.Decide("pkg", "Hex", "1.0.0") != NotAffected {
		t.Error("withdrawn advisory must affect nothing")
	}
	other := affected(nil, gitRange)
	if other.Decide("elsewhere", "Hex", "1.0.0") != NotAffected {
		t.Error("an entry for another package says nothing about this one")
	}
	if other.Decide("pkg", "npm", "1.0.0") != NotAffected {
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

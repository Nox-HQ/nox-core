package vulnsource

import (
	"encoding/json"
	"os"
	"testing"
)

// Each version sorts strictly below the next under PEP 440.
func TestComparePEP440Order(t *testing.T) {
	order := []string{
		"0.9", "1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1",
		"1.0", "1.0+local.1", "1.0.post1.dev1", "1.0.post1", "1.0.1", "1.4.0",
		"1.11a1", "1.11", "1.11.18", "2.0", "1!0.1",
	}
	for i := 0; i+1 < len(order); i++ {
		a, b := order[i], order[i+1]
		if c, ok := comparePEP440(a, b); !ok || c != -1 {
			t.Errorf("comparePEP440(%q, %q) = %d, %v; want -1, true", a, b, c, ok)
		}
		if c, ok := comparePEP440(b, a); !ok || c != 1 {
			t.Errorf("comparePEP440(%q, %q) = %d, %v; want 1, true", b, a, c, ok)
		}
	}
	for _, eq := range [][2]string{{"1.0", "1.0.0"}, {"1.0alpha1", "1.0a1"}, {"1.0-1", "1.0.post1"}, {"v2.1", "2.1.0"}} {
		if c, ok := comparePEP440(eq[0], eq[1]); !ok || c != 0 {
			t.Errorf("comparePEP440(%q, %q) = %d, %v; want 0, true", eq[0], eq[1], c, ok)
		}
	}
	if _, ok := comparePEP440("1.0", "latest"); ok {
		t.Error("an unparseable version must not be ordered")
	}
}

// GHSA-337x-4q8g-prc5 (CVE-2019-3498) affects django 1.11a1–1.11.17,
// 2.0a1–2.0.9 and 2.1a1–2.1.4. Read generically, "1.11a1" parsed as 1.0, so the
// first interval covered every 1.x from 1.0 and django 1.4.0 was reported
// affected by an advisory OSV does not return for it.
func TestDecidePEP440PrereleaseBounds(t *testing.T) {
	b, err := os.ReadFile("testdata/GHSA-337x-4q8g-prc5.json")
	if err != nil {
		t.Fatal(err)
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Verdict{
		"1.4.0":     VerdictNotAffected,
		"1.10.8":    VerdictNotAffected,
		"1.11.dev1": VerdictNotAffected, // a dev release sorts below 1.11a1
		"1.11a1":    VerdictAffected,
		"1.11.5":    VerdictAffected,
		"1.11.18":   VerdictNotAffected,
		"2.0.9":     VerdictAffected,
		"2.0.10":    VerdictNotAffected,
		"2.1.0":     VerdictAffected,
		"2.1.5":     VerdictNotAffected,
	}
	for v, want := range cases {
		if got := r.Decide("django", "PyPI", v); got != want {
			t.Errorf("Decide(django %s) = %v, want %v", v, got, want)
		}
		if got := r.Affects("django", "PyPI", v); got != (want == VerdictAffected) {
			t.Errorf("Affects(django %s) = %v, want %v", v, got, want == VerdictAffected)
		}
	}
	for v, want := range map[string]string{"1.11.5": "1.11.18", "2.0.3": "2.0.10", "2.1.0": "2.1.5", "1.4.0": ""} {
		if got := r.FixedVersion("django", "PyPI", v); got != want {
			t.Errorf("FixedVersion(django %s) = %q, want %q", v, got, want)
		}
	}
}

// Outside PyPI the generic comparator reads a segment with a letter in it as 0.
// A bound it can only read that way is not ordered, so the entry cannot be
// decided either way: "1.11a1" read as 1.0 would call 1.4.0 affected, and any
// other guess could equally call an affected version clean.
func TestDecideUnorderableBoundIsUndecidable(t *testing.T) {
	r := affected(nil, rng("ECOSYSTEM", Event{Introduced: "1.11a1"}, Event{Fixed: "1.11.18"}))
	if got := r.Decide("pkg", "Hex", "1.4.0"); got != VerdictUndecidable {
		t.Errorf("Decide = %v, want undecidable", got)
	}
	// A listed version still decides it.
	r.Affected[0].Versions = []string{"1.4.0"}
	if got := r.Decide("pkg", "Hex", "1.4.0"); got != VerdictAffected {
		t.Errorf("listed: Decide = %v, want affected", got)
	}
	// SemVer prereleases after a hyphen are ordered as before.
	r = affected(nil, rng("SEMVER", Event{Introduced: "2.0.0-beta.1"}, Event{Fixed: "2.0.1"}))
	if got := r.Decide("pkg", "Hex", "1.9.0"); got != VerdictNotAffected {
		t.Errorf("semver prerelease bound: Decide = %v, want not-affected", got)
	}
}

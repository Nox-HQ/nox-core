package vulnsource

import (
	"encoding/json"
	"testing"
)

// Debian's security tracker rates each advisory for its own release
// (ecosystem_specific.urgency: unimportant, low, medium, high, ...). A record
// that drops it on the way through, as a re-encoding service would, loses the
// one signal that says a CVSS-high entry is, in Debian, not worth fixing.
func TestDebianUrgencySurvivesARoundTrip(t *testing.T) {
	in := `{"id":"DEBIAN-CVE-2016-2781","affected":[{"package":{"name":"coreutils","ecosystem":"Debian:12"},` +
		`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"ecosystem_specific":{"urgency":"unimportant"}}]}`
	var r Record
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	if got := r.Affected[0].EcosystemSpecific.Urgency; got != "unimportant" {
		t.Fatalf("urgency %q after decoding", got)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Record
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.Affected[0].EcosystemSpecific.Urgency; got != "unimportant" {
		t.Errorf("urgency %q after re-encoding", got)
	}
}

// DistroUrgency answers for the entry naming the package, and only for it.
func TestDistroUrgencyIsPerPackage(t *testing.T) {
	r := Record{Affected: []Affected{
		{Package: Package{Name: "glibc", Ecosystem: "Debian:12"}, EcosystemSpecific: EcosystemSpecific{Urgency: "low"}},
		{Package: Package{Name: "coreutils", Ecosystem: "Debian:12"}, EcosystemSpecific: EcosystemSpecific{Urgency: "unimportant"}},
		{Package: Package{Name: "coreutils", Ecosystem: "Debian:11"}, EcosystemSpecific: EcosystemSpecific{Urgency: "high"}},
	}}
	for _, c := range []struct{ name, eco, want string }{
		{"coreutils", "Debian:12", "unimportant"},
		{"glibc", "Debian:12", "low"},
		{"coreutils", "Debian:11", "high"},
		{"zlib", "Debian:12", ""},
	} {
		if got := r.DistroUrgency(c.name, c.eco); got != c.want {
			t.Errorf("DistroUrgency(%s, %s) = %q, want %q", c.name, c.eco, got, c.want)
		}
	}
}

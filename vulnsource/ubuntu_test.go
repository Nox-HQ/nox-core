package vulnsource

import "testing"

// Ubuntu versions are dpkg versions: ~ before the end, epochs, revisions
// like 3.0.13-0ubuntu3.2.
func TestUbuntuUsesDpkgOrder(t *testing.T) {
	iv := Interval{Introduced: "0", Fixed: "3.0.13-0ubuntu3.2"}
	if !iv.coversIn("Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.1") || iv.coversIn("Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.10") {
		t.Error("Ubuntu interval did not bound with dpkg ordering (3.10 is after 3.2)")
	}
	if c := compareIn("Ubuntu:24.04:LTS", "1.1.1-1ubuntu2.1~18.04.23", "1.1.1-1ubuntu2.1"); c >= 0 {
		t.Errorf("~ backport ordered at or after its base (%d)", c)
	}
}

// Ubuntu rates an advisory with a severity entry of type "Ubuntu"
// (negligible .. critical) rather than ecosystem_specific.urgency; the rating
// is the distribution's either way.
func TestDistroUrgencyReadsUbuntuPriority(t *testing.T) {
	r := Record{
		Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"}, {Type: "Ubuntu", Score: "negligible"}},
		Affected: []Affected{{Package: Package{Name: "openssl", Ecosystem: "Ubuntu:24.04:LTS"}}},
	}
	if got := r.DistroUrgency("openssl", "Ubuntu:24.04:LTS"); got != "negligible" {
		t.Errorf("DistroUrgency = %q, want negligible", got)
	}
	// A Debian entry does not borrow a record-level Ubuntu rating.
	r.Affected = append(r.Affected, Affected{Package: Package{Name: "openssl", Ecosystem: "Debian:12"}})
	if got := r.DistroUrgency("openssl", "Debian:12"); got != "" {
		t.Errorf("Debian entry got Ubuntu's rating %q", got)
	}
}

package osv

import "testing"

// A distribution package carries its release in nox's ecosystem name, and OSV
// names the ecosystem with it: Alpine branches as "v3.22", Debian by number.
// Ubuntu's OSV names differ by support stream, so it stays unmapped (reported
// as not checked) rather than guessed.
func TestDistroEcosystems(t *testing.T) {
	for in, want := range map[string]string{
		"alpine:v3.22": "Alpine:v3.22",
		"debian:12":    "Debian:12",
	} {
		if got, ok := Ecosystem(in); !ok || got != want {
			t.Errorf("Ecosystem(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"alpine", "alpine:", "debian:", "ubuntu:24.04"} {
		if got, ok := Ecosystem(in); ok {
			t.Errorf("Ecosystem(%q) = %q; want unmapped", in, got)
		}
	}
}

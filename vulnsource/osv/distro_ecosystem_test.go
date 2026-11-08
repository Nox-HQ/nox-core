package osv

import "testing"

// A distribution package carries its release in nox's ecosystem name, and OSV
// names the ecosystem with it: Alpine branches as "v3.22", Debian by number.
// Ubuntu is named with its standard-archive stream ("24.04:LTS", or a
// release alone when it is not LTS), which the image's os-release states.
func TestDistroEcosystems(t *testing.T) {
	for in, want := range map[string]string{
		"alpine:v3.22":     "Alpine:v3.22",
		"debian:12":        "Debian:12",
		"ubuntu:24.04:LTS": "Ubuntu:24.04:LTS",
		"ubuntu:25.10":     "Ubuntu:25.10",
		"almalinux:9":      "AlmaLinux:9",
		"rocky:9":          "Rocky Linux:9",
	} {
		if got, ok := Ecosystem(in); !ok || got != want {
			t.Errorf("Ecosystem(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	// A Pro or FIPS stream needs a subscription an image does not carry;
	// answering for it would describe packages the image does not have.
	for _, in := range []string{"alpine", "alpine:", "debian:", "ubuntu:", "ubuntu:Pro:24.04:LTS", "ubuntu:Pro:FIPS:22.04:LTS",
		// Red Hat publishes per product repository, which an image's rpmdb
		// does not record; answering for a guessed one is answering for
		// packages the image may not have.
		"rhel:9"} {
		if got, ok := Ecosystem(in); ok {
			t.Errorf("Ecosystem(%q) = %q; want unmapped", in, got)
		}
	}
}

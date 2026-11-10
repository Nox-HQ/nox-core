package vulnsource

import "testing"

// opensslRecord has the shape OSV publishes for an OpenSSL CVE: no package,
// a GIT range on the upstream repository, and the affected release tags.
func opensslRecord(tags ...string) Record {
	return Record{ID: "CVE-2099-0001", Affected: []Affected{{
		Ranges:   []Range{{Type: "GIT", Repo: "https://github.com/openssl/openssl", Events: []Event{{Introduced: "abc"}, {Fixed: "def"}}}},
		Versions: tags,
	}}}
}

// OSV knows OpenSSL by its repository and release tags, not as a package.
func TestUpstreamOpenSSLQuery(t *testing.T) {
	up, ok := UpstreamFor("openssl")
	if !ok || up.Repo != "https://github.com/openssl/openssl" || up.Tag("3.5.9") != "openssl-3.5.9" {
		t.Fatalf("UpstreamFor(openssl) = %+v, %v", up, ok)
	}
	if _, ok := UpstreamFor("npm"); ok {
		t.Error("npm is not an upstream-by-repository package")
	}
}

// The record names no fixed release, only commits. Within an OpenSSL 3.x
// series the fix ships in the release after the last affected one: checked
// on 2026-11-10 against OpenSSL's own CVE records for 99 CVEs, 295 series, 0
// disagreements. Outside a 3.x numbered series nothing is derived.
func TestOpenSSLFixIsTheReleaseAfterTheLastAffected(t *testing.T) {
	r := opensslRecord("openssl-3.0.13", "openssl-3.0.14", "openssl-3.0.15", "openssl-3.5.0", "openssl-3.5.1", "OpenSSL_1_1_1w")
	for installed, want := range map[string]string{
		"3.0.13": "3.0.16",
		"3.0.15": "3.0.16",
		"3.5.0":  "3.5.2",
		"3.5.2":  "", // not an affected tag: nothing to fix
		"3.2.1":  "", // a series the advisory does not list
		"1.1.1w": "", // not a 3.x numbered series
		"bogus":  "",
	} {
		if got := r.FixedVersion("openssl", "GIT", installed); got != want {
			t.Errorf("FixedVersion(openssl, %s) = %q, want %q", installed, got, want)
		}
	}
}

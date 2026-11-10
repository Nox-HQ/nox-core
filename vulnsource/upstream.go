package vulnsource

import (
	"strconv"
	"strings"
)

// Upstream is software OSV knows by its source repository rather than as a
// package in an ecosystem: OpenSSL's advisories carry a GIT range on
// github.com/openssl/openssl and the affected release tags. nox finds such
// software bundled inside binaries (Node.js links its own OpenSSL), where no
// package manager lists it.
type Upstream struct {
	// Repo is the repository OSV names, which is also the query's package.
	Repo string
	// Tag turns a release version into the repository's tag for it, which is
	// the query's version.
	Tag func(version string) string
}

var upstreams = map[string]Upstream{
	"openssl": {Repo: "https://github.com/openssl/openssl", Tag: func(v string) string { return "openssl-" + v }},
}

// UpstreamFor returns how to ask OSV about a nox ecosystem known only by its
// repository.
func UpstreamFor(ecosystem string) (Upstream, bool) {
	u, ok := upstreams[ecosystem]
	return u, ok
}

// opensslFix derives the fixed release of an OpenSSL advisory for installed.
// The record names fixing commits, not releases; within a 3.x series OpenSSL
// ships the fix in the release after the last affected one. Checked on
// 2026-11-10 against OpenSSL's own CVE records (the cvelistV5 entries OSV
// generated these from): 99 CVEs, 295 series, 0 disagreements. Nothing is
// derived when installed is not an affected tag, or outside a 3.x numbered
// series (1.1.1's letter releases, and its fixes are not public).
func (r *Record) opensslFix(installed string) string {
	major, minor, _, ok := opensslVersion(installed)
	if !ok || major < 3 {
		return ""
	}
	up := upstreams["openssl"]
	last, affected := -1, false
	for _, a := range r.Affected {
		if !rangesOn(a, up.Repo) {
			continue
		}
		for _, tag := range a.Versions {
			v, ok := strings.CutPrefix(tag, "openssl-")
			if !ok {
				continue
			}
			mj, mn, p, ok := opensslVersion(v)
			if !ok || mj != major || mn != minor {
				continue
			}
			if v == installed {
				affected = true
			}
			last = max(last, p)
		}
	}
	if !affected || last < 0 {
		return ""
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(last+1)
}

// rangesOn reports whether an affected entry's ranges are on repo, or carry
// no repository at all (the versions list then stands alone).
func rangesOn(a Affected, repo string) bool {
	for _, rg := range a.Ranges {
		if rg.Type == "GIT" && rg.Repo != "" && rg.Repo != repo {
			return false
		}
	}
	return true
}

func opensslVersion(v string) (major, minor, patch int, ok bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	n := make([]int, 3)
	for i, s := range parts {
		x, err := strconv.Atoi(s)
		if err != nil || x < 0 {
			return 0, 0, 0, false
		}
		n[i] = x
	}
	return n[0], n[1], n[2], true
}

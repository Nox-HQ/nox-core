package vulnsource

import (
	"strconv"
	"strings"
)

// RPM versions, in rpm's own order. OSV's AlmaLinux and Rocky Linux
// advisories carry fixed versions as epoch:version-release
// ("1:3.0.1-41.el9_0"), and the semver-like fallback misorders them: it reads
// el9_4.10 as below el9_4.2 and ignores the epoch.

func isRPM(ecosystem string) bool {
	return hasEcosystemPrefix(ecosystem, "AlmaLinux") || hasEcosystemPrefix(ecosystem, "Rocky Linux")
}

// compareRPM orders two [epoch:]version[-release] strings as rpm does: the
// epoch (missing is 0) as a number, then version and release by rpmvercmp, as
// rpm.vercmp does: a missing release sorts below any release.
func compareRPM(a, b string) (int, bool) {
	ae, av, ar, ok1 := splitEVR(a)
	be, bv, br, ok2 := splitEVR(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if ae != be {
		return sgn(ae - be), true
	}
	if c := rpmvercmp(av, bv); c != 0 {
		return c, true
	}
	return rpmvercmp(ar, br), true
}

func splitEVR(v string) (epoch int, version, release string, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, "", "", false
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		n, err := strconv.Atoi(v[:i])
		if err != nil || n < 0 {
			return 0, "", "", false
		}
		epoch, v = n, v[i+1:]
	}
	// rpm takes the release after the last hyphen (rpmverParse).
	version = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		version, release = v[:i], v[i+1:]
	}
	return epoch, version, release, true
}

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// rpmvercmp is rpm's comparison of a version or a release (lib/rpmvercmp.c).
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// "~" sorts before everything, the end of the string included.
		if i < len(a) && a[i] == '~' || j < len(b) && b[j] == '~' {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		// "^" sorts after the end of the string, before anything else.
		if i < len(a) && a[i] == '^' || j < len(b) && b[j] == '^' {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlnum(a[i]) && !isDigit(a[i]) {
				i++
			}
			for j < len(b) && isAlnum(b[j]) && !isDigit(b[j]) {
				j++
			}
		}
		x, y := a[si:i], b[sj:j]
		if y == "" {
			// Segments of different kinds: the numeric one is newer.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				return sgn(len(x) - len(y))
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}

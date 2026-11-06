package vulnsource

import (
	"strconv"
	"strings"
)

// Distribution package versions, in each distribution's own order. OSV
// publishes Alpine and Debian advisories with the distribution's version
// strings, and ordering them as semver gets the fix wrong: it puts 1.0-r10
// before 1.0-r9, and 1.0~rc1 after 1.0.

func isAlpine(ecosystem string) bool { return hasEcosystemPrefix(ecosystem, "Alpine") }
func isDebian(ecosystem string) bool { return hasEcosystemPrefix(ecosystem, "Debian") }

// hasEcosystemPrefix matches "Alpine" and "Alpine:v3.22" alike.
func hasEcosystemPrefix(ecosystem, name string) bool {
	return strings.EqualFold(ecosystem, name) ||
		(len(ecosystem) > len(name) && strings.EqualFold(ecosystem[:len(name)+1], name+":"))
}

// compareDpkg orders two Debian versions as dpkg does: epoch, then upstream,
// then revision, each of the latter two by verrevcmp.
func compareDpkg(a, b string) (int, bool) {
	ae, au, ar, ok1 := splitDpkg(a)
	be, bu, br, ok2 := splitDpkg(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if ae != be {
		if ae < be {
			return -1, true
		}
		return 1, true
	}
	if c := verrevcmp(au, bu); c != 0 {
		return c, true
	}
	return verrevcmp(ar, br), true
}

// splitDpkg splits [epoch:]upstream[-revision]. A missing revision is "0",
// which verrevcmp treats as equal to an empty one.
func splitDpkg(v string) (epoch int, upstream, revision string, ok bool) {
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
	upstream, revision = v, "0"
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	}
	if upstream == "" || upstream[0] < '0' || upstream[0] > '9' {
		return 0, "", "", false
	}
	return epoch, upstream, revision, true
}

// dpkgOrder is the weight dpkg gives a non-digit character: "~" before the end
// of the string, the end before letters, letters before everything else.
func dpkgOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// verrevcmp is dpkg's comparison of an upstream version or a revision.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := dpkgOrder(a, i), dpkgOrder(b, j)
			if ac != bc {
				return sgn(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sgn(firstDiff)
		}
	}
	return 0
}

// apkToken is one comparable part of an Alpine version.
type apkToken struct {
	kind int // apkNumber, apkLetter, apkSuffix, apkRevision
	n    int
}

const (
	apkNumber = iota
	apkLetter
	apkSuffix
	apkRevision
	apkEnd
)

// apkSuffixRank orders apk's suffixes: the pre-release ones below no suffix
// (0), the post-release ones above.
var apkSuffixRank = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

// parseAPK reads number(.number)*[letter](_suffix[number])*[~hash][-rN].
func parseAPK(v string) ([]apkToken, bool) {
	v = strings.TrimSpace(v)
	rev := 0
	if i := strings.LastIndex(v, "-r"); i >= 0 {
		n, err := strconv.Atoi(v[i+2:])
		if err != nil {
			return nil, false
		}
		rev, v = n, v[:i]
	}
	if i := strings.IndexByte(v, '~'); i >= 0 { // a commit hash orders nothing
		v = v[:i]
	}
	main, rest, _ := strings.Cut(v, "_")
	var toks []apkToken
	letter := byte(0)
	if n := len(main); n > 0 && main[n-1] >= 'a' && main[n-1] <= 'z' {
		letter, main = main[n-1], main[:n-1]
	}
	for _, part := range strings.Split(main, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		toks = append(toks, apkToken{kind: apkNumber, n: n})
	}
	if letter != 0 {
		toks = append(toks, apkToken{kind: apkLetter, n: int(letter)})
	}
	for rest != "" {
		var suf string
		suf, rest, _ = strings.Cut(rest, "_")
		name := strings.TrimRight(suf, "0123456789")
		rank, known := apkSuffixRank[name]
		if !known {
			return nil, false
		}
		num := 0
		if digits := suf[len(name):]; digits != "" {
			num, _ = strconv.Atoi(digits)
		}
		toks = append(toks, apkToken{kind: apkSuffix, n: rank}, apkToken{kind: apkNumber, n: num})
	}
	toks = append(toks, apkToken{kind: apkRevision, n: rev})
	return toks, true
}

// compareAPK orders two Alpine versions as apk-tools does.
func compareAPK(a, b string) (int, bool) {
	at, ok1 := parseAPK(a)
	bt, ok2 := parseAPK(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < len(at) || i < len(bt); i++ {
		x, y := apkAt(at, i), apkAt(bt, i)
		if x.kind != y.kind {
			return apkKindOrder(x) - apkKindOrder(y), true
		}
		if x.n != y.n {
			return sgn(x.n - y.n), true
		}
	}
	return 0, true
}

func apkAt(t []apkToken, i int) apkToken {
	if i < len(t) {
		return t[i]
	}
	return apkToken{kind: apkEnd}
}

// apkKindOrder decides between two versions whose next parts differ in kind.
// A further number means a longer version (newer); a letter is newer than none;
// a suffix is newer or older than none by its rank; the revision closes both.
func apkKindOrder(t apkToken) int {
	switch t.kind {
	case apkNumber:
		return 3
	case apkLetter:
		return 2
	case apkSuffix:
		if t.n < 0 {
			return 0 // pre-release: older than whatever the other side has
		}
		return 2
	}
	return 1 // revision or end
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func sgn(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// DistroUrgency is the distribution's own rating of r for pkgName in the
// named ecosystem ("Debian:12"), or "" when the entry gives none. Only the
// entry naming that package and release answers: the same CVE can be
// unimportant in one release and high in another.
func (r *Record) DistroUrgency(pkgName, wireEcosystem string) string {
	for _, a := range r.Affected {
		if a.Package.Name == pkgName && strings.EqualFold(a.Package.Ecosystem, wireEcosystem) {
			return a.EcosystemSpecific.Urgency
		}
	}
	return ""
}

package vulnsource

import (
	"math"
	"strconv"
	"strings"
)

// PyPI advisories bound their ranges with PEP 440 versions, and PEP 440 spells
// a prerelease without a separator: "1.11a1". The generic comparator reads that
// segment as 0, so "1.11a1" sorts as 1.0 and a range from 1.11a1 covers every
// 1.x. PyPI ranges are therefore ordered here, by the specification's own rule.

// pepVersion is a parsed PEP 440 version. The pre, post and dev fields hold the
// sort keys PEP 440 assigns, sentinels included, so comparison is field by field.
type pepVersion struct {
	epoch   int
	release []int
	pre     [2]int // phase rank (a=0, b=1, rc=2) and number
	post    int
	dev     int
	local   []string
}

const (
	pepLow  = math.MinInt
	pepHigh = math.MaxInt
)

// parsePEP440 parses v, reporting false for anything the pattern does not
// recognise or whose numbers do not fit an int.
func parsePEP440(v string) (pepVersion, bool) {
	m := pep440.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil {
		return pepVersion{}, false
	}
	ok := true
	num := func(s string) int {
		if s == "" {
			return 0
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			ok = false
		}
		return n
	}
	p := pepVersion{epoch: num(m[1]), post: pepLow, dev: pepHigh}
	for _, seg := range strings.Split(m[2], ".") {
		p.release = append(p.release, num(seg))
	}
	switch {
	case m[3] != "":
		rank := map[string]int{"alpha": 0, "a": 0, "beta": 1, "b": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}[m[3]]
		p.pre = [2]int{rank, num(m[4])}
	case m[5] == "" && m[6] == "" && m[8] != "":
		p.pre = [2]int{pepLow, 0} // a bare dev release sorts below every prerelease
	default:
		p.pre = [2]int{pepHigh, 0} // a final release sorts above its prereleases
	}
	switch {
	case m[5] != "":
		p.post = num(m[5])
	case m[6] != "":
		p.post = num(m[7])
	}
	if m[8] != "" {
		p.dev = num(m[9])
	}
	if m[10] != "" {
		p.local = strings.FieldsFunc(m[10], func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	}
	return p, ok
}

// comparePEP440 orders a and b under PEP 440, returning -1, 0 or 1. ok is false
// when either is not a PEP 440 version; the caller must not order them then.
func comparePEP440(a, b string) (int, bool) {
	x, okA := parsePEP440(a)
	y, okB := parsePEP440(b)
	if !okA || !okB {
		return 0, false
	}
	for _, c := range []int{
		cmpInt(x.epoch, y.epoch),
		cmpRelease(x.release, y.release),
		cmpInt(x.pre[0], y.pre[0]),
		cmpInt(x.pre[1], y.pre[1]),
		cmpInt(x.post, y.post),
		cmpInt(x.dev, y.dev),
		cmpLocal(x.local, y.local),
	} {
		if c != 0 {
			return c, true
		}
	}
	return 0, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cmpRelease compares release segments, missing trailing segments as zero.
func cmpRelease(a, b []int) int {
	for i := range max(len(a), len(b)) {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// cmpLocal orders local version labels: none sorts lowest, numeric segments
// above alphanumeric ones, and a longer label above its own prefix.
func cmpLocal(a, b []string) int {
	for i := range min(len(a), len(b)) {
		an, aErr := strconv.Atoi(a[i])
		bn, bErr := strconv.Atoi(b[i])
		switch {
		case aErr == nil && bErr == nil:
			if c := cmpInt(an, bn); c != 0 {
				return c
			}
		case aErr == nil:
			return 1
		case bErr == nil:
			return -1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a), len(b))
}

// orderedIn reports whether version can be ordered in the ecosystem: as PEP 440
// for PyPI, and otherwise by the generic comparator without it zeroing a
// lettered segment of the release ("1.11a1"). A prerelease after a hyphen is
// ordered generically and does not disqualify a version.
func orderedIn(ecosystem, version string) bool {
	if isPyPI(ecosystem) {
		_, ok := parsePEP440(version)
		return ok
	}
	if !ComparableVersion(version) {
		return false
	}
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	v, _, _ = strings.Cut(v, "+")
	core, _, _ := strings.Cut(v, "-")
	return strings.Trim(core, "0123456789.") == ""
}

// compareIn orders a and b in the ecosystem: PEP 440 for PyPI when both parse,
// the generic comparator otherwise.
func compareIn(ecosystem, a, b string) int {
	if isPyPI(ecosystem) {
		if c, ok := comparePEP440(a, b); ok {
			return c
		}
	}
	return CompareVersions(a, b)
}

// coversIn is Interval.Covers with the ecosystem's ordering.
func (iv Interval) coversIn(ecosystem, installed string) bool {
	if !isPyPI(ecosystem) {
		return iv.Covers(installed)
	}
	if _, ok := parsePEP440(installed); !ok {
		return iv.Covers(installed)
	}
	bound := func(b string) (int, bool) { return comparePEP440(installed, b) }
	if iv.Introduced != "" && iv.Introduced != "0" {
		if c, ok := bound(iv.Introduced); !ok || c < 0 {
			return false
		}
	}
	switch {
	case iv.Fixed != "":
		c, ok := bound(iv.Fixed)
		return ok && c < 0
	case iv.LastAffected != "":
		c, ok := bound(iv.LastAffected)
		return ok && c <= 0
	}
	return true
}

func isPyPI(ecosystem string) bool { return strings.EqualFold(ecosystem, "PyPI") }

package vulnsource

import (
	"regexp"
	"strings"
)

// Maven advisories bound their ranges with Maven versions, and Maven orders a
// qualifier it does not know above the release it qualifies: "33.7.2-jre" is
// the 33.7.2 release built for the JRE, not a prerelease of it. The generic
// comparator reads every hyphen as a SemVer prerelease, so it put each Guava
// "-jre" and "-android" build below its own fix and reported it vulnerable.
// Maven ranges are therefore ordered here, by OSV's implementation of the
// Maven version specification (osv/ecosystems/maven.py), which is what OSV
// answers with and so what the mirror must agree with. Where Maven itself and
// the written specification differ, that implementation already chose.

// mavenToken is one prefixed token of a Maven version. null marks the padding
// a shorter version is extended with; it takes no part in equality.
type mavenToken struct {
	prefix string // "" for the first token, else "." or "-"
	value  string // lower-cased; a number has no leading zeros
	null   bool
}

type mavenVersion []mavenToken

// mavenKeywords are the qualifiers that sort before every other, in order. ""
// is the release itself ("ga", "final" and "release" are spelled that way).
var mavenKeywords = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// mavenTransition finds a boundary between a digit and a non-digit, which
// Maven treats as a hyphen. It matches the pair, so callers split after its
// first byte; overlapping pairs ("1a1") are found by stepping one byte at a
// time.
var mavenTransition = regexp.MustCompile(`[0-9][^0-9]|[^0-9][0-9]`)

func isNumber(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// parseMaven splits v into prefixed tokens and trims the trailing null values,
// following osv/ecosystems/maven.py step for step.
func parseMaven(v string) mavenVersion {
	var out mavenVersion
	prefix := ""
	for {
		end := strings.IndexAny(v, ".-")
		part := v
		if end >= 0 {
			part = v[:end]
		}
		out = appendMavenPart(out, prefix, part)
		if end < 0 {
			break
		}
		prefix, v = v[end:end+1], v[end+1:]
	}
	return trimMaven(out)
}

// appendMavenPart adds the tokens of one separator-free part, splitting it at
// each digit/non-digit transition.
func appendMavenPart(out mavenVersion, prefix, part string) mavenVersion {
	var cuts []int
	for i := 0; i+1 < len(part); i++ {
		if mavenTransition.MatchString(part[i : i+2]) {
			cuts = append(cuts, i+1)
		}
	}
	cuts = append(cuts, len(part))
	prev := 0
	for j, cut := range cuts {
		if j > 0 {
			prefix = "-"
		}
		cur := strings.ToLower(part[prev:cut])
		switch cur {
		case "":
			cur = "0"
		case "cr":
			cur = "rc"
		case "ga", "final", "release":
			cur = ""
		}
		if cut != len(part) { // shorthand only when a number follows
			switch cur {
			case "a":
				cur = "alpha"
			case "b":
				cur = "beta"
			case "m":
				cur = "milestone"
			}
		}
		if isNumber(cur) {
			cur = trimZeros(cur)
		}
		out = append(out, mavenToken{prefix: prefix, value: cur})
		prev = cut
	}
	return out
}

// trimMaven drops the trailing null values (0, "", "final", "ga") from the
// end, then again before each remaining hyphen, always keeping one token.
func trimMaven(v mavenVersion) mavenVersion {
	i := len(v) - 1
	for i > 0 {
		switch v[i].value {
		case "0", "", "final", "ga":
			v = append(v[:i], v[i+1:]...)
			i--
			continue
		}
		for i >= 0 && v[i].prefix != "-" {
			i--
		}
		i--
	}
	return v
}

func (v mavenVersion) String() string {
	var b strings.Builder
	for _, t := range v {
		b.WriteString(t.prefix + t.value)
	}
	return b.String()
}

// compareMaven orders a and b as OSV orders Maven versions: -1, 0 or 1.
func compareMaven(a, b string) int {
	x, y := parseMaven(a), parseMaven(b)
	for i := range max(len(x), len(y)) {
		var l, r mavenToken
		switch {
		case i >= len(x):
			l, r = mavenPad(y[i]), y[i]
		case i >= len(y):
			l, r = x[i], mavenPad(x[i])
		default:
			l, r = x[i], y[i]
		}
		if l.prefix == r.prefix && l.value == r.value {
			continue
		}
		if l.less(r) {
			return -1
		}
		return 1
	}
	return 0
}

// mavenPad is the null value a shorter version is padded with opposite t:
// 0 against a ".", the empty qualifier against a "-".
func mavenPad(t mavenToken) mavenToken {
	if t.prefix == "-" {
		return mavenToken{prefix: "-", null: true}
	}
	return mavenToken{prefix: ".", value: "0", null: true}
}

func (t mavenToken) less(o mavenToken) bool {
	if t.prefix != o.prefix {
		return t.rank() < o.rank()
	}
	tn, on := isNumber(t.value), isNumber(o.value)
	switch {
	case tn && on:
		return cmpDigits(t.value, o.value) < 0
	case tn && !t.null: // a number sorts above a qualifier, unless it is padding
		return false
	case on && !o.null:
		return true
	}
	ti, oi := keywordRank(t.value), keywordRank(o.value)
	if ti == len(mavenKeywords) && oi == len(mavenKeywords) {
		return t.value < o.value
	}
	return ti < oi
}

// rank orders tokens whose prefixes differ:
// ".qualifier" < "-qualifier" < "-number" < ".number".
func (t mavenToken) rank() int {
	switch {
	case isNumber(t.value) && t.prefix == "-":
		return 2
	case isNumber(t.value):
		return 3
	case t.prefix == "-":
		return 1
	}
	return 0
}

func keywordRank(q string) int {
	for i, k := range mavenKeywords {
		if k == q {
			return i
		}
	}
	return len(mavenKeywords)
}

// cmpDigits compares two digit strings without leading zeros by value, at any
// width: Maven versions carry timestamps wider than an int64.
func cmpDigits(a, b string) int {
	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func isMaven(ecosystem string) bool { return strings.EqualFold(ecosystem, "Maven") }

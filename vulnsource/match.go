package vulnsource

import (
	"regexp"
	"strings"
)

// Version matching lives here, in the package both sides import, for the same
// reason core/evidence owns the definition of CONFIRMED: a mirror and a client
// that each decide for themselves which versions an advisory affects will
// eventually disagree, and the disagreement will look like a vulnerability
// appearing or vanishing rather than like a bug.
//
// The comparison is deliberately conservative. A version that cannot be ordered
// is never treated as affected, because guessing would mean picking a fix at
// random — and a scanner that recommends a downgrade is worse than one that
// says nothing.

// Interval is one contiguous affected range from an advisory: versions from
// Introduced (inclusive) up to Fixed (exclusive), or through LastAffected
// (inclusive). Fixed is empty when the interval names no fix — an unfixed
// release branch.
type Interval struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Covers reports whether the installed version falls inside the interval.
func (iv Interval) Covers(installed string) bool {
	if !ComparableVersion(installed) {
		return false
	}
	// "0" is OSV's "since the beginning"; comparing against it directly would
	// exclude prereleases of 0.0.0, which sort below it.
	if iv.Introduced != "" && iv.Introduced != "0" {
		if !ComparableVersion(iv.Introduced) || CompareVersions(installed, iv.Introduced) < 0 {
			return false
		}
	}
	switch {
	case iv.Fixed != "":
		return ComparableVersion(iv.Fixed) && CompareVersions(installed, iv.Fixed) < 0
	case iv.LastAffected != "":
		return ComparableVersion(iv.LastAffected) && CompareVersions(installed, iv.LastAffected) <= 0
	}
	return true // introduced with no upper bound: still unfixed
}

// ComparableVersion reports whether v carries an ordering CompareVersions can
// be trusted with. A value whose leading segment is not numeric — "latest",
// "unknown", a git SHA, an empty string — does not.
func ComparableVersion(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	lead, _, _ := strings.Cut(v, ".")
	lead, _, _ = strings.Cut(lead, "-")
	lead, _, _ = strings.Cut(lead, "+")
	if lead == "" {
		return false
	}
	for _, r := range lead {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// CompareVersions orders two dotted-numeric versions, returning -1, 0, or 1.
// Every numeric segment takes part ("6.6.0.7" > "6.6.0.3"; NuGet and PyPI use
// four and more), missing trailing segments count as zero ("1.2" == "1.2.0"),
// and a release sorts above its own prereleases.
func CompareVersions(a, b string) int {
	an, apre := splitVersion(a)
	bn, bpre := splitVersion(b)

	for i := range max(len(an), len(bn)) {
		var x, y int
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}

	switch {
	case apre == bpre:
		return 0
	case apre == "": // release beats prerelease
		return 1
	case bpre == "":
		return -1
	case apre < bpre:
		return -1
	default:
		return 1
	}
}

// splitVersion breaks "v1.2.3.4-rc1" into its numeric segments and prerelease.
// A segment with a non-digit in it counts as zero, as it always has.
func splitVersion(v string) (nums []int, prerelease string) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "+"); i >= 0 { // build metadata is not ordered
		v = v[:i]
	}
	core, pre, _ := strings.Cut(v, "-")
	for _, part := range strings.Split(core, ".") {
		n := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				n = 0
				break
			}
			n = n*10 + int(r-'0')
		}
		nums = append(nums, n)
	}
	return nums, pre
}

// AffectedIntervals expands the advisory's affected entries for the given
// package into flat intervals.
//
// OSV expresses a package's affected versions either as several `affected`
// entries with one range each, or as one range with several introduced/fixed
// pairs. Both mean the same thing and both occur in real advisories, so both
// are flattened here.
//
// wireEcosystem is the ecosystem name as it appears inside the advisory
// (OSV's own vocabulary, e.g. "Go", "npm", "PyPI"). Callers holding a nox
// ecosystem name must map it first; this package deliberately does not know
// that mapping, which belongs to whichever wire protocol produced the record.
func (r *Record) AffectedIntervals(pkgName, wireEcosystem string) []Interval {
	want := strings.ToLower(pkgName)
	var out []Interval

	for _, aff := range r.Affected {
		if !strings.EqualFold(aff.Package.Name, want) {
			continue
		}
		if aff.Package.Ecosystem != "" && wireEcosystem != "" &&
			!strings.EqualFold(aff.Package.Ecosystem, wireEcosystem) {
			continue
		}
		for _, rng := range aff.Ranges {
			cur := Interval{}
			open := false
			for _, e := range rng.Events {
				switch {
				case e.Introduced != "":
					if open {
						out = append(out, cur)
					}
					cur, open = Interval{Introduced: e.Introduced}, true
				case e.Fixed != "":
					cur.Fixed = e.Fixed
					out = append(out, cur)
					cur, open = Interval{}, false
				case e.LastAffected != "":
					cur.LastAffected = e.LastAffected
					out = append(out, cur)
					cur, open = Interval{}, false
				}
			}
			if open {
				out = append(out, cur)
			}
		}
	}
	return out
}

// Retracted reports whether the source database has withdrawn the advisory.
func (r *Record) Retracted() bool { return r.Withdrawn != "" }

// Affects reports whether the advisory covers pkgName at the given version.
//
// This is what a source holding a local corpus must answer, and what a source
// proxying a remote API gets answered for it. Both must agree, or the same
// package version is vulnerable according to one and clean according to the
// other.
func (r *Record) Affects(pkgName, wireEcosystem, version string) bool {
	// A withdrawn advisory affects nothing, whatever its ranges still say.
	if r.Retracted() {
		return false
	}
	for _, iv := range r.AffectedIntervals(pkgName, wireEcosystem) {
		if iv.Covers(version) {
			return true
		}
	}
	return false
}

// FixedVersion returns the version the installed one must move to in order to
// clear the advisory, or "" when that cannot be established.
//
// An advisory covering a package with maintained release branches names one fix
// per branch. Reporting any fix other than the one for the branch in use is not
// a cosmetic mislabel: the fix for an older branch is a *lower* version than
// what is installed, so the remediation reads as a downgrade — to something
// plausibly vulnerable to a different advisory, and certainly a functional
// regression. So the interval containing the installed version selects the fix,
// not the order the advisory happens to list its ranges in.
//
// "" is returned whenever no interval contains the installed version: outside
// the ranges, on a branch with no fix yet, or with a version string that cannot
// be ordered. That is a genuine "we do not know", and any answer invented to
// fill it would reintroduce the defect in a new form.
func (r *Record) FixedVersion(pkgName, wireEcosystem, installed string) string {
	intervals := r.AffectedIntervals(pkgName, wireEcosystem)

	// A single interval leaves nothing to select between, and its bounds are
	// the ones the source already matched the installed version against.
	if len(intervals) == 1 {
		return intervals[0].Fixed
	}

	best := ""
	for _, iv := range intervals {
		if iv.Fixed == "" || !iv.Covers(installed) {
			continue
		}
		// Overlapping intervals are malformed data, but if they occur the
		// smallest upgrade that clears the advisory is the honest answer.
		if best == "" || CompareVersions(iv.Fixed, best) < 0 {
			best = iv.Fixed
		}
	}
	return best
}

// Verdict is a three-valued answer to "does this advisory affect that version".
// The third value exists because two-valued matching turns "the data cannot
// say" into "not affected", which is a false all-clear.
type Verdict int

const (
	// VerdictNotAffected: every entry naming the package is decidable and none covers
	// the version.
	VerdictNotAffected Verdict = iota
	// VerdictAffected: the explicit versions list names the version, or an ordered
	// range covers it.
	VerdictAffected
	// VerdictUndecidable: an entry naming the package carries nothing a package-level
	// match can be made from (no versions list and only GIT or unknown range
	// types, or no ranges at all), and nothing else decided it Affected.
	VerdictUndecidable
)

func (v Verdict) String() string {
	switch v {
	case VerdictAffected:
		return "affected"
	case VerdictUndecidable:
		return "undecidable"
	}
	return "not-affected"
}

// Decide decides whether the advisory affects pkgName at version, following
// OSV's own rule for package queries:
//
//   - the version appearing in an entry's explicit versions list is affected;
//   - SEMVER and ECOSYSTEM ranges are ordered with the version comparator;
//   - GIT ranges hold commit hashes, not versions, and are never compared. They
//     only answer commit queries.
//
// An entry that lists versions explicitly, and has no range of another type, is
// fully decided by that list plus its ordered ranges, so a version absent from
// both is VerdictNotAffected. An entry that also carries a GIT (or unknown-type)
// range, or has no versions list with only such ranges, or has no ranges at all,
// cannot be decided, and yields VerdictUndecidable rather than VerdictNotAffected unless another
// entry or an ordered range already says Affected. A withdrawn advisory affects
// nothing.
//
// The versions list is matched with the ecosystem's own notion of equality, as
// OSV does (see matchList): PEP 440 for PyPI, exact strings elsewhere. A list
// entry that is numerically equal to version but not equal by that rule
// ("1.4" against "1.4.0" in npm) is VerdictUndecidable, never NotAffected,
// because the mirror must not answer clean where OSV would say Affected.
func (r *Record) Decide(pkgName, wireEcosystem, version string) Verdict {
	if r.Retracted() {
		return VerdictNotAffected
	}
	undecidable := false
	for _, aff := range r.Affected {
		if !strings.EqualFold(aff.Package.Name, pkgName) {
			continue
		}
		if aff.Package.Ecosystem != "" && wireEcosystem != "" &&
			!strings.EqualFold(aff.Package.Ecosystem, wireEcosystem) {
			continue
		}
		listed := matchList(aff.Versions, eco(aff, wireEcosystem), version)
		if listed == listEqual {
			return VerdictAffected
		}
		ordered := Record{Affected: []Affected{{Package: aff.Package}}}
		sawOrdered := false
		for _, rg := range aff.Ranges {
			if rg.Type == "SEMVER" || rg.Type == "ECOSYSTEM" {
				ordered.Affected[0].Ranges = append(ordered.Affected[0].Ranges, rg)
				sawOrdered = true
			}
		}
		if sawOrdered && ordered.Affects(pkgName, wireEcosystem, version) {
			return VerdictAffected
		}
		if listed == listNear {
			// A list entry that is numerically the same version but spelled
			// differently: OSV decides it with the ecosystem's own equality,
			// which the mirror cannot vouch for. Not NotAffected.
			undecidable = true
		}
		hasOther := len(aff.Ranges) > len(ordered.Affected[0].Ranges)
		switch {
		case len(aff.Versions) == 0 && !sawOrdered:
			undecidable = true
		case hasOther:
			// Neither the list nor an ordered range names the version, but a
			// range of another type (GIT: resolved through the repository's
			// tags, which this record does not carry) might. OSV's own
			// package-query rule ignores GIT ranges and every probe agrees,
			// but the cost of not trusting that is a handful of entries and
			// the cost of trusting it wrongly is a false all-clear.
			undecidable = true
		}
	}
	if undecidable {
		return VerdictUndecidable
	}
	return VerdictNotAffected
}

// listMatch is how an explicit versions list relates to a queried version.
type listMatch int

const (
	// listAbsent: no entry equals the version by the ecosystem's own rule, and
	// none is numerically equal to it either.
	listAbsent listMatch = iota
	// listNear: no entry is equal by the ecosystem's rule, but some entry is
	// numerically equal under CompareVersions while spelled differently
	// ("1.4" against "1.4.0"). The mirror cannot say whether OSV treats the
	// two as one version.
	listNear
	// listEqual: an entry names the version by the ecosystem's own rule.
	listEqual
)

// matchList relates the explicit list to version.
//
// OSV matches a package query against the versions list with the ecosystem's
// native version comparison, so what "the same version" means depends on the
// ecosystem. PyPI follows PEP 440, where 1.4 == 1.4.0; npm, Go and crates.io
// follow SemVer, where those are distinct. The mirror must never decide
// NotAffected where OSV would say Affected, so:
//
//   - PyPI entries equal under PEP 440 normalization are listEqual;
//   - everywhere else only an exact match (leading "v" tolerated) is listEqual;
//   - an entry that is not equal by that rule but is numerically equal under
//     CompareVersions is listNear, which Decide turns into Undecidable so the
//     caller asks live OSV. For PyPI this applies only when one side is not a
//     well-formed PEP 440 version; two well-formed, different versions are
//     different.
func matchList(list []string, wireEcosystem, version string) listMatch {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	pypi := strings.EqualFold(wireEcosystem, "PyPI")
	vKey, vOK := pep440Key(version)
	result := listAbsent
	for _, s := range list {
		if s == version || strings.TrimPrefix(s, "v") == v {
			return listEqual
		}
		if pypi && vOK {
			if sKey, sOK := pep440Key(s); sOK {
				if sKey == vKey {
					return listEqual
				}
				continue
			}
		}
		if ComparableVersion(s) && ComparableVersion(version) && CompareVersions(s, version) == 0 {
			result = listNear
		}
	}
	return result
}

// pep440 matches a PEP 440 version in the spellings the specification
// normalizes. Groups: 1 epoch, 2 release, 3-4 pre keyword and number, 5
// implicit post number ("1.0-1"), 6-7 post keyword and number, 8-9 dev keyword
// and number, 10 local segment.
var pep440 = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d+)?)?` +
	`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?` +
	`(?:[-_.]?(dev)[-_.]?(\d+)?)?` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

// pep440Key returns a canonical string such that two PEP 440 versions are
// equal exactly when their keys are equal. The epoch is part of the key, so
// "1!2.0" never equals "2.0". ok is false for anything the pattern does not
// recognise; the caller must not claim equality or difference on that basis.
func pep440Key(version string) (key string, ok bool) {
	m := pep440.FindStringSubmatch(strings.ToLower(strings.TrimSpace(version)))
	if m == nil {
		return "", false
	}
	var b strings.Builder
	b.WriteString(trimZeros(m[1]) + "!")
	rel := strings.Split(m[2], ".")
	for len(rel) > 1 && trimZeros(rel[len(rel)-1]) == "0" {
		rel = rel[:len(rel)-1]
	}
	for i := range rel {
		rel[i] = trimZeros(rel[i])
	}
	b.WriteString(strings.Join(rel, "."))
	if m[3] != "" {
		pre := map[string]string{"alpha": "a", "a": "a", "beta": "b", "b": "b",
			"c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}[m[3]]
		b.WriteString("." + pre + trimZeros(m[4]))
	}
	switch {
	case m[5] != "":
		b.WriteString(".post" + trimZeros(m[5]))
	case m[6] != "":
		b.WriteString(".post" + trimZeros(m[7]))
	}
	if m[8] != "" {
		b.WriteString(".dev" + trimZeros(m[9]))
	}
	if m[10] != "" {
		segs := strings.FieldsFunc(m[10], func(r rune) bool { return r == '-' || r == '_' || r == '.' })
		for i, seg := range segs {
			if strings.Trim(seg, "0123456789") == "" {
				segs[i] = trimZeros(seg)
			}
		}
		b.WriteString("+" + strings.Join(segs, "."))
	}
	return b.String(), true
}

// trimZeros strips leading zeros from a digit string; "" and "000" become "0".
func trimZeros(s string) string {
	if t := strings.TrimLeft(s, "0"); t != "" {
		return t
	}
	return "0"
}

// eco is the ecosystem to compare versions under: the caller's, else the one
// the advisory entry names.
func eco(aff Affected, wireEcosystem string) string {
	if wireEcosystem != "" {
		return wireEcosystem
	}
	return aff.Package.Ecosystem
}

// OrderedIntervals is AffectedIntervals restricted to the range types whose
// events are versions: SEMVER and ECOSYSTEM. A GIT range's events are commit
// hashes; AffectedIntervals folds them in beside real versions, which is right
// for a caller that wants everything the advisory says and wrong for one that
// reports a "fixed in" version or compares an installed version to the bounds.
func (r *Record) OrderedIntervals(pkgName, wireEcosystem string) []Interval {
	ordered := Record{ID: r.ID, Withdrawn: r.Withdrawn}
	for _, aff := range r.Affected {
		keep := aff
		keep.Ranges = nil
		for _, rg := range aff.Ranges {
			if rg.Type == "SEMVER" || rg.Type == "ECOSYSTEM" {
				keep.Ranges = append(keep.Ranges, rg)
			}
		}
		ordered.Affected = append(ordered.Affected, keep)
	}
	return ordered.AffectedIntervals(pkgName, wireEcosystem)
}

// ListedVersions returns the explicit affected-versions lists of the entries
// naming pkgName, de-duplicated, in first-seen order.
func (r *Record) ListedVersions(pkgName, wireEcosystem string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, aff := range r.Affected {
		if !strings.EqualFold(aff.Package.Name, pkgName) {
			continue
		}
		if aff.Package.Ecosystem != "" && wireEcosystem != "" &&
			!strings.EqualFold(aff.Package.Ecosystem, wireEcosystem) {
			continue
		}
		for _, v := range aff.Versions {
			if _, dup := seen[v]; !dup {
				seen[v] = struct{}{}
				out = append(out, v)
			}
		}
	}
	return out
}

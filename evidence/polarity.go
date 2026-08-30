package evidence

// Polarity says whether a claim argues FOR a proposition, AGAINST it, or
// neither.
//
// nox has always been good at accumulating reasons to worry and had no way to
// record a reason to stop worrying. A refutation could only be expressed by
// deleting the finding, which loses the reasoning, or by not producing it,
// which is indistinguishable from never having looked.
//
// Two rules matter more than the type itself, and both are enforced in
// aggregation rather than left to convention:
//
//   - A missing supporting claim is not a refutation. An empty ledger, or one
//     that simply holds nothing about a subject, says nothing.
//   - A failed or unavailable analysis is not a refutation. That is what
//     PolarityUnknown is for: it records that something was looked at and
//     produced no answer, which must never read as "and therefore it is fine".
type Polarity string

// Polarity values.
const (
	// PolarityUnspecified is the zero value and is read as PolaritySupports.
	//
	// This is a deliberate compatibility choice, not an oversight. Every claim
	// that existed before polarity was a supporting claim by construction —
	// producers only ever recorded reasons to believe. Reading an unset field
	// as Unknown instead would silently zero the evidence in both consumers on
	// the version bump, which is a far worse default than assuming what was
	// unambiguously true of every claim already written.
	PolarityUnspecified Polarity = ""
	// PolaritySupports argues that the proposition holds.
	PolaritySupports Polarity = "supports"
	// PolarityRefutes argues that the proposition does NOT hold. Only an
	// affirmative finding belongs here — evidence that something is safe, not
	// the absence of evidence that it is dangerous.
	PolarityRefutes Polarity = "refutes"
	// PolarityUnknown records that the question was asked and not answered: an
	// analysis ran and could not decide, timed out, or was unsupported for the
	// input. It weighs nothing in either direction and, critically, is not a
	// refutation.
	PolarityUnknown Polarity = "unknown"
)

// Effective resolves the zero value, so callers never branch on "".
func (p Polarity) Effective() Polarity {
	if p == PolarityUnspecified {
		return PolaritySupports
	}
	return p
}

// Valid reports whether p is a defined polarity (including the zero value,
// which is defined to mean Supports).
func (p Polarity) Valid() bool {
	switch p {
	case PolarityUnspecified, PolaritySupports, PolarityRefutes, PolarityUnknown:
		return true
	}
	return false
}

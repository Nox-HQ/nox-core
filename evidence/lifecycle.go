package evidence

// Status is a claim's position in its own lifecycle.
//
// Evidence cannot be immortal once an intelligence network, research agents
// and plugins are producing it. An advisory is withdrawn. A reproduction turns
// out to have been an artefact of the harness. A maintainer disputes a report.
// An upstream fix changes the affected ranges out from under a version match.
//
// A retracted claim is not deleted. It stays in the ledger — the audit trail
// is the product — and weighs nothing, exactly as an unrecognised Kind does.
// Removing it instead would make a ledger that was once CONFIRMED silently
// become one that never had the evidence, and "we were wrong" is a different
// statement from "we never said it".
//
// Staleness is deliberately absent. It is a function of a clock and a policy,
// and this package reads no clock. Callers that expire evidence do so by
// setting a Status themselves, which keeps every derived verdict reproducible
// from its inputs.
type Status string

// Claim lifecycle states.
const (
	// StatusActive is the zero value: the claim stands.
	StatusActive Status = ""
	// StatusSuperseded means a later claim about the same subject replaces this
	// one as the current reading. The superseded claim was not wrong; it is
	// simply no longer the answer.
	StatusSuperseded Status = "superseded"
	// StatusRetracted means the producer withdrew the claim.
	StatusRetracted Status = "retracted"
	// StatusInvalidated means someone else established the claim was wrong —
	// a reproduction that did not hold up, a version range corrected upstream.
	StatusInvalidated Status = "invalidated"
	// StatusReplaced means the claim was restated in a different form, usually
	// at a different strength, and the restatement is authoritative.
	StatusReplaced Status = "replaced"
)

// Valid reports whether s is a defined status.
func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusSuperseded, StatusRetracted, StatusInvalidated, StatusReplaced:
		return true
	}
	return false
}

// Live reports whether the claim still counts toward a verdict. Only
// StatusActive does. An unrecognised status is treated as not live, so a
// status this build does not understand fails closed rather than counting.
func (s Status) Live() bool { return s == StatusActive }

package evidence

import "fmt"

// SubjectKind classifies what a claim is *about*.
//
// Before subjects existed, a Ledger was a bag of claims and Strongest() picked
// the heaviest one in it. That is sound only while every claim concerns the
// same proposition, and in practice it does not:
//
//	OSV advisory: package X is vulnerable          (public_advisory, 100)
//	static analysis: the affected call path is unreachable here
//	                                          ↓
//	                              Strongest() = the advisory
//	                                          ↓
//	                          "therefore exploitable"
//
// Two true statements about two different things, aggregated into one false
// conclusion. The advisory is about a package; the refutation is about a call
// path; nothing in the model knew the difference. Typed subjects make that
// aggregation impossible rather than merely discouraged.
//
// The set is deliberately closed and small. It is a vocabulary for security
// reasoning, not an ontology of software.
type SubjectKind string

// Subject kinds. Each is a thing a security claim can be about.
const (
	// SubjectPackage is a package at a version — the granularity advisories
	// speak in, and the coarsest thing worth making a claim about.
	SubjectPackage SubjectKind = "package"
	// SubjectSymbol is a named function, method, type or constant. Advisories
	// increasingly scope to symbols within a package, and "the package is
	// affected" and "the affected symbol is used here" are different claims.
	SubjectSymbol SubjectKind = "symbol"
	// SubjectFlow is a dataflow from a source to a sink. One flow is one
	// security condition however many times it is observed.
	SubjectFlow SubjectKind = "flow"
	// SubjectCallPath is an ordered chain of calls, typically from an entry
	// point to a symbol. It is what makes a reachability claim auditable
	// instead of a boolean.
	SubjectCallPath SubjectKind = "call_path"
	// SubjectInput is a value crossing a trust boundary — a request parameter,
	// an environment variable, a message payload.
	SubjectInput SubjectKind = "input"
	// SubjectControl is a security control: a sanitizer, an authorization
	// check, a guardrail. Claims about controls are how PREVENTED is reached
	// honestly rather than by observing nothing.
	SubjectControl SubjectKind = "control"
	// SubjectHypothesis is a proposed exploit — the thing dynamic validation
	// tries to confirm or refute.
	SubjectHypothesis SubjectKind = "hypothesis"
	// SubjectCandidate is a rule match at a location, before anything has
	// adjudicated it: "SEC-240 matched at config/app.go:41".
	//
	// It was missing from the first seven, and the omission is instructive. The
	// other kinds were derived from the dependency-applicability chain — a
	// package is affected, a symbol belongs to it, a path reaches it — which is
	// the argument that motivated typed subjects in the first place. But that
	// chain describes what nox reasons ABOUT, not what nox mostly PRODUCES. A
	// pattern scanner's primary object is the candidate match, and every claim
	// a refiner makes ("this match lies in a comment", "this value is a
	// placeholder", "this is a bare prefix with no token body") is a claim
	// about one.
	//
	// A candidate is deliberately not a Finding. A finding is an adjudicated
	// output; a candidate is the observation that may or may not become one,
	// and the whole point of recording claims against it is that some
	// candidates are refuted and therefore never become findings at all. Those
	// are exactly the ones whose reasoning used to vanish.
	SubjectCandidate SubjectKind = "candidate"
)

// validSubjectKinds is the closed set. An unrecognised kind is not silently
// accepted: like an unrecognised evidence Kind, it is retained for the audit
// trail and contributes nothing.
var validSubjectKinds = map[SubjectKind]bool{
	SubjectPackage:    true,
	SubjectSymbol:     true,
	SubjectFlow:       true,
	SubjectCallPath:   true,
	SubjectInput:      true,
	SubjectControl:    true,
	SubjectHypothesis: true,
	SubjectCandidate:  true,
}

// Valid reports whether k is a defined subject kind.
func (k SubjectKind) Valid() bool { return validSubjectKinds[k] }

// Subject identifies one proposition-bearing thing.
//
// ID is opaque to this package and must be stable and unique within the Kind:
// "pkg:golang/golang.org/x/crypto@0.17.0", "golang.org/x/crypto/openpgp.Read",
// a flow fingerprint. The package never parses it — comparison is equality —
// so callers may choose any scheme provided they choose it consistently.
//
// The zero Subject is the "unattributed" subject. It exists so that a ledger
// written before subjects, or by a producer that does not yet assign them,
// keeps behaving exactly as it did: every claim lands in one bucket, which is
// the single-subject case.
type Subject struct {
	Kind SubjectKind `json:"kind"`
	ID   string      `json:"id"`
}

// Zero reports whether s is the unattributed subject.
func (s Subject) Zero() bool { return s.Kind == "" && s.ID == "" }

// Valid reports whether s names a defined kind and carries an identity. The
// zero Subject is not Valid — it is the absence of a subject, not a subject.
func (s Subject) Valid() bool { return s.Kind.Valid() && s.ID != "" }

// String renders a subject as "kind:id", stable and comparable.
func (s Subject) String() string {
	if s.Zero() {
		return "unattributed"
	}
	return fmt.Sprintf("%s:%s", s.Kind, s.ID)
}

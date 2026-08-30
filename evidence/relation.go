package evidence

import (
	"fmt"
	"sort"
)

// RelationKind names a directed link between two subjects.
//
// The vocabulary exists to express one chain, which is the chain every
// applicability argument walks:
//
//	package affected
//	  → the vulnerable symbol belongs to that package      (contains)
//	  → this application links that symbol                 (uses)
//	  → a call path actually reaches it                    (reaches)
//	  → the flow into it originates at an untrusted input  (originates)
//	  → no control stands between them                     (guards)
//	  → therefore: an exploit hypothesis                   (concerns)
//
// Six kinds, and the restraint is the design. A larger vocabulary would let two
// producers describe the same relationship two ways, and a relation graph whose
// edges do not mean one thing is worse than no graph at all: it looks like
// structure and reasons like noise.
type RelationKind string

// Relation kinds.
const (
	// RelContains links a package to a symbol it ships. The edge advisories
	// implicitly assert and version-matching alone cannot.
	RelContains RelationKind = "contains"
	// RelUses links a call path or package to a symbol the build links. Linked
	// is weaker than called: it means the code is present, not that it runs.
	RelUses RelationKind = "uses"
	// RelReaches links a call path or flow to a symbol it actually reaches.
	// This is the edge that separates "we ship it" from "we run it".
	RelReaches RelationKind = "reaches"
	// RelOriginates links a flow to the input it starts at. Without it a flow
	// is internal plumbing; with it the flow starts outside the trust boundary.
	RelOriginates RelationKind = "originates"
	// RelGuards links a control to what it protects. Its ABSENCE is not a
	// vulnerability and its presence is not safety — a guard edge is a claim
	// like any other, and the claim about it can be refuted.
	RelGuards RelationKind = "guards"
	// RelConcerns links a hypothesis to the subject it is about, so an exploit
	// hypothesis and the flow it exploits are one argument rather than two.
	RelConcerns RelationKind = "concerns"
)

// validRelationKinds is the closed set.
var validRelationKinds = map[RelationKind]bool{
	RelContains:   true,
	RelUses:       true,
	RelReaches:    true,
	RelOriginates: true,
	RelGuards:     true,
	RelConcerns:   true,
}

// Valid reports whether k is a defined relation kind.
func (k RelationKind) Valid() bool { return validRelationKinds[k] }

// Relation is one directed edge between two subjects.
//
// A relation is an assertion, not a fact. That a call path reaches a symbol is
// exactly the kind of thing a static analysis can get wrong, so a relation
// carries its own evidence rather than standing on its own authority — which
// is what keeps "reachable" from becoming the unauditable boolean the whole
// design is trying to avoid.
type Relation struct {
	From Subject      `json:"from"`
	Kind RelationKind `json:"kind"`
	To   Subject      `json:"to"`
	// Ledger holds the claims for and against this edge. An edge with an empty
	// ledger is asserted without evidence, which Graph.Validate reports.
	Ledger Ledger `json:"ledger,omitzero"`
}

// Valid reports whether r names defined endpoints and a defined kind.
func (r Relation) Valid() bool {
	return r.From.Valid() && r.To.Valid() && r.Kind.Valid()
}

// String renders an edge as "from -kind-> to".
func (r Relation) String() string {
	return fmt.Sprintf("%s -%s-> %s", r.From, r.Kind, r.To)
}

// Graph is a set of subjects and the relations between them.
//
// It answers "what evidence do we have about this specific proposition?" —
// which is what a bag of claims could never answer — and it composes across
// subjects rather than letting them compete. Composition into a verdict is
// deliberately NOT here: this package supplies the structure and the arithmetic
// within a subject, and adjudication across subjects belongs to the consumer
// that owns the security judgement.
//
// The zero Graph is usable.
type Graph struct {
	Relations []Relation `json:"relations,omitempty"`
}

// Add appends a relation. Invalid relations are kept, so nothing vanishes from
// the audit trail, and Validate reports them.
func (g *Graph) Add(r Relation) { g.Relations = append(g.Relations, r) }

// Len returns the number of relations.
func (g *Graph) Len() int { return len(g.Relations) }

// From returns the relations leaving s, in insertion order.
func (g *Graph) From(s Subject) []Relation {
	var out []Relation
	for _, r := range g.Relations {
		if r.From == s {
			out = append(out, r)
		}
	}
	return out
}

// To returns the relations arriving at s, in insertion order.
func (g *Graph) To(s Subject) []Relation {
	var out []Relation
	for _, r := range g.Relations {
		if r.To == s {
			out = append(out, r)
		}
	}
	return out
}

// Subjects returns every distinct subject the graph mentions, sorted for
// determinism.
func (g *Graph) Subjects() []Subject {
	seen := make(map[Subject]bool, len(g.Relations)*2)
	for _, r := range g.Relations {
		seen[r.From] = true
		seen[r.To] = true
	}
	out := make([]Subject, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Validate reports structural problems: undefined kinds, subjects without an
// identity, and edges asserted with no evidence at all.
//
// The last is not pedantry. An edge with an empty ledger is a claim nobody has
// to justify, and a reachability graph assembled out of those is precisely the
// unauditable "reachable: true" this model exists to replace.
func (g *Graph) Validate() []string {
	var errs []string
	for i, r := range g.Relations {
		if !r.Kind.Valid() {
			errs = append(errs, fmt.Sprintf("relation[%d]: %q is not a known relation kind", i, r.Kind))
		}
		if !r.From.Valid() {
			errs = append(errs, fmt.Sprintf("relation[%d]: source subject %s is not a valid subject", i, r.From))
		}
		if !r.To.Valid() {
			errs = append(errs, fmt.Sprintf("relation[%d]: target subject %s is not a valid subject", i, r.To))
		}
		if r.Ledger.Len() == 0 {
			errs = append(errs, fmt.Sprintf("relation[%d]: %s is asserted with no evidence", i, r))
		}
	}
	return errs
}

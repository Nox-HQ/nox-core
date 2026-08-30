package evidence

import "sort"

// Authority says which evidence kinds a producer is permitted to assert.
//
// Provenance already records where a claim came from. What it could not do is
// stop a producer from assigning itself an epistemic rank it has no way to
// earn. A lexical analyzer can honestly claim that a match sits in a code
// region rather than a comment. Nothing prevented it from emitting
// KindDynamicExploit at strength 95, and once it did, the ledger could not tell
// that claim apart from an oracle that actually watched an invariant break.
//
// This matters most for the producers nox does not write. Plugins run
// out-of-process and the intelligence network accepts claims from
// installations nox has never seen; both are exactly the place where "the
// producer decides how much its own word is worth" stops being acceptable.
//
// An unauthorised claim is never dropped. It stays in the ledger — the audit
// trail has to record that a producer overreached, and deleting the evidence
// of overreach is the one response that makes the problem invisible — and it
// weighs nothing, the same treatment an unrecognised Kind gets.
//
// The zero Authority permits everything. Enforcement is opt-in so that adding
// this type does not silently re-weight existing ledgers in either consumer;
// a caller asks for it by passing a non-empty Authority to the *Under methods.
type Authority struct {
	// permitted maps a Provenance.Source to the kinds it may assert. A source
	// absent from the map is permitted nothing — the table is an allowlist,
	// because a policy that fails open is not a policy.
	permitted map[string]map[Kind]bool
}

// NewAuthority builds an authority from a source-to-kinds table. Passing no
// entries yields an authority that permits nothing, which is the correct
// fail-closed reading of "an allowlist with nothing on it"; callers wanting no
// enforcement pass the zero Authority instead.
func NewAuthority(table map[string][]Kind) Authority {
	permitted := make(map[string]map[Kind]bool, len(table))
	for source, kinds := range table {
		set := make(map[Kind]bool, len(kinds))
		for _, k := range kinds {
			set[k] = true
		}
		permitted[source] = set
	}
	return Authority{permitted: permitted}
}

// DefaultAuthority is the authority nox and the intelligence service share.
//
// The shape of the table is the argument. Producers that observe are permitted
// to observe; producers that reproduce are permitted to claim reproduction;
// and the two claims that end an argument outright — a maintainer's word and a
// published advisory — can only come from a maintainer or an advisory feed.
// No producer is permitted every kind, including nox's own.
func DefaultAuthority() Authority {
	return NewAuthority(map[string][]Kind{
		// The scanner observes and analyses. It never reproduces anything: it
		// does not execute the code under scan, by design.
		"nox-scan": {KindHeuristic, KindStatic},
		// Dynamic validation executes against a target, so it — and only it —
		// may claim a runtime oracle saw an invariant break.
		"nox-attack": {KindHeuristic, KindStatic, KindControlledReproduction, KindDynamicExploit},
		// The intelligence network aggregates what installations report and
		// what research proposes. It confirms nothing on its own.
		"nox-intel": {KindIndependentObservation, KindResearchHypothesis},
		// An LLM may judge, and its judgement is labelled as such wherever it
		// appears. It may claim nothing else.
		"nox-assist": {KindSemantic},
		// A public database asserts advisories and nothing else.
		"osv": {KindPublicAdvisory},
		// A researcher may hypothesise, read the code, and reproduce.
		"researcher": {KindResearchHypothesis, KindSourceConfirmed, KindControlledReproduction},
		// A maintainer's confirmation is theirs alone to give.
		"maintainer": {KindMaintainerConfirmed},
	})
}

// Enforcing reports whether a is configured to restrict anything. The zero
// Authority is not enforcing and permits every claim.
func (a Authority) Enforcing() bool { return a.permitted != nil }

// Permits reports whether source may assert kind. A non-enforcing authority
// permits everything; an enforcing one permits only what its table lists, so
// an unknown source is permitted nothing.
func (a Authority) Permits(source string, k Kind) bool {
	if !a.Enforcing() {
		return true
	}
	return a.permitted[source][k]
}

// Sources lists the sources the authority knows, sorted for determinism.
func (a Authority) Sources() []string {
	out := make([]string, 0, len(a.permitted))
	for s := range a.permitted {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Kinds lists the kinds source may assert, sorted for determinism. It returns
// nil for a non-enforcing authority, which permits everything and therefore has
// no list to give.
func (a Authority) Kinds(source string) []Kind {
	if !a.Enforcing() {
		return nil
	}
	set := a.permitted[source]
	out := make([]Kind, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

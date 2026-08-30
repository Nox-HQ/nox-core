package evidence

import "testing"

// pkgSubject and pathSubject are the two subjects in the motivating bug: an
// advisory speaks about a package, a reachability analysis speaks about a call
// path, and aggregating them was how two true statements became one false
// conclusion.
var (
	pkgSubject  = Subject{Kind: SubjectPackage, ID: "pkg:golang/golang.org/x/crypto@0.17.0"}
	pathSubject = Subject{Kind: SubjectCallPath, ID: "main→handler→openpgp.Read"}
)

// TestAdvisoryAboutAPackageCannotConcludeAboutACallPath is the bug that
// motivated typed subjects, written as a test.
//
// Both claims are correct. The advisory really does say the package is
// affected; the analysis really did establish the path is unreachable. The old
// model put them in one bag, took the strongest, and answered "public advisory,
// strength 100" — concluding exploitability from evidence that was never about
// the code path at all.
func TestAdvisoryAboutAPackageCannotConcludeAboutACallPath(t *testing.T) {
	l := &Ledger{}
	l.Add(Claim{
		Kind: KindPublicAdvisory, Subject: pkgSubject,
		Statement:  "GO-2026-5932 affects golang.org/x/crypto/openpgp",
		Provenance: Provenance{Source: "osv"},
	})
	l.Add(Claim{
		Kind: KindStatic, Subject: pathSubject, Polarity: PolarityRefutes,
		Statement:  "the affected package is not linked by this build",
		Provenance: Provenance{Source: "nox-scan"},
	})

	if !l.Mixed() {
		t.Fatal("ledger holding claims about a package and a call path must report Mixed")
	}
	if got := l.ConfidenceAbout(pkgSubject); got != ConfidenceConfirmed {
		t.Errorf("confidence about the package = %s, want CONFIRMED; the advisory is still true", got)
	}
	if got := l.ConfidenceAbout(pathSubject); got != ConfidenceLow {
		t.Errorf("confidence about the call path = %s, want LOW; it was deterministically refuted", got)
	}
	if got := l.Confidence(); got.AtLeast(ConfidenceHigh) {
		t.Errorf("a mixed ledger answered %s — the strongest claim in a bag of unrelated "+
			"propositions must never become the verdict for all of them", got)
	}
}

// TestMissingSupportIsNotRefutation pins the first of the two rules polarity
// exists to enforce. Silence says nothing.
func TestMissingSupportIsNotRefutation(t *testing.T) {
	empty := &Ledger{}
	if got := empty.ConfidenceAbout(pkgSubject); got != ConfidenceLow {
		t.Errorf("empty ledger = %s, want LOW", got)
	}
	if empty.Conflict(pkgSubject) {
		t.Error("an empty ledger reported a conflict; there is nothing to conflict")
	}

	// A ledger with claims about a DIFFERENT subject says nothing about this one.
	other := &Ledger{}
	other.Add(Claim{Kind: KindStatic, Subject: pathSubject})
	if got := other.ConfidenceAbout(pkgSubject); got != ConfidenceLow {
		t.Errorf("claims about another subject gave %s about this one, want LOW", got)
	}
}

// TestFailedAnalysisIsNotRefutation pins the second rule, and it is the one
// that matters most: an analysis that ran and could not answer must not read
// as an analysis that cleared the code.
func TestFailedAnalysisIsNotRefutation(t *testing.T) {
	l := &Ledger{}
	l.Add(Claim{
		Kind: KindStatic, Subject: pathSubject,
		Statement:  "taint reaches the sink",
		Provenance: Provenance{Source: "nox-scan"},
	})
	withSupport := l.ConfidenceAbout(pathSubject)

	l.Add(Claim{
		Kind: KindStatic, Subject: pathSubject, Polarity: PolarityUnknown,
		Statement:  "reachability analysis timed out",
		Provenance: Provenance{Source: "nox-scan"},
	})

	if got := l.ConfidenceAbout(pathSubject); got != withSupport {
		t.Errorf("an unresolved analysis moved confidence %s -> %s; "+
			"'we could not tell' must weigh nothing in either direction", withSupport, got)
	}
	if l.Conflict(pathSubject) {
		t.Error("an unknown-polarity claim was counted as a conflicting one")
	}
}

// TestStrongerRefutationDefeatsWeakerSupport is the arithmetic that makes
// refutation worth recording at all.
func TestStrongerRefutationDefeatsWeakerSupport(t *testing.T) {
	l := &Ledger{}
	l.Add(Claim{Kind: KindHeuristic, Subject: pathSubject, Statement: "pattern matched"})
	if got := l.ConfidenceAbout(pathSubject); got != ConfidenceLow {
		t.Fatalf("heuristic alone = %s, want LOW", got)
	}

	l.Add(Claim{
		Kind: KindStatic, Subject: pathSubject, Polarity: PolarityRefutes,
		Statement: "every argument at the call site is constant",
	})
	if got := l.ConfidenceAbout(pathSubject); got != ConfidenceLow {
		t.Errorf("static refutation of a heuristic = %s, want LOW", got)
	}

	// And the other way round: a heuristic must not unmake a static finding.
	l2 := &Ledger{}
	l2.Add(Claim{Kind: KindStatic, Subject: pathSubject, Statement: "taint path resolved"})
	l2.Add(Claim{Kind: KindHeuristic, Subject: pathSubject, Polarity: PolarityRefutes,
		Statement: "looks like test code"})
	if got := l2.ConfidenceAbout(pathSubject); got != ConfidenceMedium {
		t.Errorf("heuristic refutation of a static claim = %s, want MEDIUM (support stands)", got)
	}
}

// TestSemanticJudgementCannotUnmakeAReproducedExploit is the protection rule.
// The ladder exists so that judgement never outranks proof — in either
// direction. A model that let an LLM refute a reproduction would have the same
// defect as one that let an LLM confirm it.
func TestSemanticJudgementCannotUnmakeAReproducedExploit(t *testing.T) {
	hyp := Subject{Kind: SubjectHypothesis, ID: "h-1"}
	l := &Ledger{}
	l.Add(Claim{Kind: KindDynamicExploit, Subject: hyp,
		Statement: "oracle observed the invariant break", Provenance: Provenance{Source: "nox-attack"}})
	l.Add(Claim{Kind: KindPublicAdvisory, Subject: hyp, Polarity: PolarityRefutes,
		Statement: "advisory says the affected range excludes this version"})

	// A public advisory IS deterministic and IS stronger, so it does overturn.
	if got := l.ConfidenceAbout(hyp); got != ConfidenceLow {
		t.Errorf("a stronger deterministic refutation gave %s, want LOW", got)
	}

	// A semantic judgement, however confident it sounds, does not.
	l2 := &Ledger{}
	l2.Add(Claim{Kind: KindDynamicExploit, Subject: hyp,
		Statement: "oracle observed the invariant break", Provenance: Provenance{Source: "nox-attack"}})
	l2.Add(Claim{Kind: KindSemantic, Subject: hyp, Polarity: PolarityRefutes,
		Statement: "the model believes this is a false positive"})
	if got := l2.ConfidenceAbout(hyp); got != ConfidenceConfirmed {
		t.Errorf("an LLM refutation reduced a reproduced exploit to %s; "+
			"judgement must never overturn a deterministic oracle", got)
	}
}

// TestEqualStrengthContradictionIsVisible checks that a genuine standoff is
// reported rather than silently resolved in someone's favour.
func TestEqualStrengthContradictionIsVisible(t *testing.T) {
	l := &Ledger{}
	l.Add(Claim{Kind: KindStatic, Subject: pathSubject, Statement: "reaches the sink"})
	l.Add(Claim{Kind: KindStatic, Subject: pathSubject, Polarity: PolarityRefutes,
		Statement: "a sanitizer dominates the path"})

	if !l.Conflict(pathSubject) {
		t.Error("two equally strong contradictory claims did not report a conflict")
	}
	if got := l.ConfidenceAbout(pathSubject); got != ConfidenceLow {
		t.Errorf("an undecided proposition scored %s, want LOW", got)
	}
}

// TestRetractedEvidenceStopsCountingAndStaysVisible pins the lifecycle rule.
func TestRetractedEvidenceStopsCountingAndStaysVisible(t *testing.T) {
	hyp := Subject{Kind: SubjectHypothesis, ID: "h-2"}
	l := &Ledger{}
	l.Add(Claim{Kind: KindControlledReproduction, Subject: hyp,
		Statement: "reproduced in a sandbox", Provenance: Provenance{Source: "researcher"}})
	if got := l.ConfidenceAbout(hyp); got != ConfidenceConfirmed {
		t.Fatalf("reproduction = %s, want CONFIRMED", got)
	}

	l.Claims[0].Status = StatusInvalidated
	if got := l.ConfidenceAbout(hyp); got == ConfidenceConfirmed {
		t.Error("an invalidated reproduction still confirmed")
	}
	if l.Len() != 1 {
		t.Error("an invalidated claim was dropped from the ledger; " +
			"'we were wrong' must not become 'we never said it'")
	}

	for _, st := range []Status{StatusSuperseded, StatusRetracted, StatusReplaced, Status("from-a-newer-build")} {
		l.Claims[0].Status = st
		if got := l.ConfidenceAbout(hyp); got != ConfidenceLow {
			t.Errorf("a %q claim contributed %s, want LOW", st, got)
		}
	}
}

// TestProducerCannotAssertBeyondItsAuthority is B5. A producer that names
// itself the wrong thing does not get the rank it asked for.
func TestProducerCannotAssertBeyondItsAuthority(t *testing.T) {
	hyp := Subject{Kind: SubjectHypothesis, ID: "h-3"}
	auth := DefaultAuthority()

	overreach := Claim{
		Kind: KindDynamicExploit, Subject: hyp,
		Statement:  "the lexer declares this exploited",
		Provenance: Provenance{Source: "nox-scan"},
	}
	l := &Ledger{}
	l.Add(overreach)

	if got := l.ConfidenceAbout(hyp); got != ConfidenceConfirmed {
		t.Fatalf("without enforcement the claim stands at %s, want CONFIRMED "+
			"(the zero Authority must not change existing behaviour)", got)
	}
	if got := l.ConfidenceAboutUnder(hyp, auth); got != ConfidenceLow {
		t.Errorf("nox-scan asserting a dynamic exploit scored %s under the default "+
			"authority, want LOW", got)
	}
	if un := l.Unauthorized(auth); len(un) != 1 {
		t.Errorf("Unauthorized returned %d claims, want 1 — an overreaching claim "+
			"must stay visible rather than be deleted", len(un))
	}
	if l.Len() != 1 {
		t.Error("an unauthorized claim was dropped from the audit trail")
	}

	// The producer that legitimately owns the kind is unaffected.
	ok := &Ledger{}
	ok.Add(Claim{Kind: KindDynamicExploit, Subject: hyp,
		Provenance: Provenance{Source: "nox-attack"}})
	if got := ok.ConfidenceAboutUnder(hyp, auth); got != ConfidenceConfirmed {
		t.Errorf("nox-attack asserting a dynamic exploit scored %s, want CONFIRMED", got)
	}
}

// TestAuthorityIsAnAllowlist checks the fail-closed direction: a source nobody
// listed is permitted nothing, and the zero Authority is the only thing that
// permits everything.
func TestAuthorityIsAnAllowlist(t *testing.T) {
	auth := DefaultAuthority()
	if auth.Permits("some-plugin-nobody-vetted", KindHeuristic) {
		t.Error("an unlisted source was permitted a claim; the table must be an allowlist")
	}
	for _, source := range auth.Sources() {
		if auth.Permits(source, Kind("invented-kind")) {
			t.Errorf("%s was permitted an undefined kind", source)
		}
	}
	if !auth.Permits("maintainer", KindMaintainerConfirmed) {
		t.Error("a maintainer may not confirm their own project's vulnerability")
	}
	if auth.Permits("nox-intel", KindDynamicExploit) {
		t.Error("the intelligence network was permitted to claim a runtime exploit it cannot run")
	}
	if auth.Permits("nox-scan", KindPublicAdvisory) {
		t.Error("the scanner was permitted to publish advisories")
	}

	var permissive Authority
	if !permissive.Permits("anyone", KindDynamicExploit) {
		t.Error("the zero Authority must permit everything, so adding this type " +
			"changes no existing verdict")
	}
	if permissive.Enforcing() {
		t.Error("the zero Authority reported itself as enforcing")
	}
}

// TestLegacyLedgersAreUnchanged is the compatibility guarantee, stated as a
// test rather than as a promise in a commit message. Every claim written before
// this change carries three zero values, and all three must read as what was
// unambiguously true of it.
func TestLegacyLedgersAreUnchanged(t *testing.T) {
	l := &Ledger{}
	l.Add(Claim{Kind: KindStatic, Provenance: Provenance{SourceID: "a"}})
	l.Add(Claim{Kind: KindStatic, Provenance: Provenance{SourceID: "b"}})

	if l.Mixed() {
		t.Error("a ledger of subject-less claims reported as mixed")
	}
	if got := l.Confidence(); got != ConfidenceHigh {
		t.Errorf("two independent static claims = %s, want HIGH as before", got)
	}
	for _, c := range l.Claims {
		if !c.Live() || !c.Supports() {
			t.Error("a claim with zero Polarity/Status must be live and supporting")
		}
	}
}

// TestSubjectAndRelationVocabulariesAreClosed guards the restraint. Both sets
// are meant to stay small; an unrecognised member of either must fail closed
// rather than be quietly accepted.
func TestSubjectAndRelationVocabulariesAreClosed(t *testing.T) {
	if (SubjectKind("service")).Valid() {
		t.Error("an undefined subject kind validated")
	}
	if (RelationKind("relates_to")).Valid() {
		t.Error("an undefined relation kind validated")
	}
	if (Subject{Kind: SubjectPackage}).Valid() {
		t.Error("a subject with no identity validated")
	}
	if !(Subject{}).Zero() {
		t.Error("the zero Subject did not report itself as unattributed")
	}
	if (Subject{}).Valid() {
		t.Error("the zero Subject validated; it is the absence of a subject, not one")
	}
}

// TestGraphRejectsEvidenceFreeEdges pins the reason relations carry ledgers: a
// reachability graph assembled from unjustified edges is the unauditable
// "reachable: true" the whole model exists to replace.
func TestGraphRejectsEvidenceFreeEdges(t *testing.T) {
	sym := Subject{Kind: SubjectSymbol, ID: "openpgp.Read"}
	var g Graph
	g.Add(Relation{From: pkgSubject, Kind: RelContains, To: sym})

	errs := g.Validate()
	if len(errs) != 1 {
		t.Fatalf("Validate() returned %d problems, want 1: %v", len(errs), errs)
	}

	var backed Ledger
	backed.Add(Claim{Kind: KindPublicAdvisory, Statement: "advisory scopes to this import path"})
	g.Relations[0].Ledger = backed
	if errs := g.Validate(); len(errs) != 0 {
		t.Errorf("an evidence-backed edge failed validation: %v", errs)
	}

	if got := len(g.From(pkgSubject)); got != 1 {
		t.Errorf("From(package) returned %d edges, want 1", got)
	}
	if got := len(g.To(pkgSubject)); got != 0 {
		t.Errorf("To(package) returned %d edges, want 0", got)
	}
	if got := len(g.Subjects()); got != 2 {
		t.Errorf("Subjects() returned %d, want 2", got)
	}
}

// TestCorroborationCountsBelieversNotParticipants separates the two
// independence questions. Confusing them is how a disputed report gets
// published on the strength of the dispute.
func TestCorroborationCountsBelieversNotParticipants(t *testing.T) {
	l := &Ledger{}
	l.Add(Claim{Kind: KindStatic, Subject: pkgSubject,
		Provenance: Provenance{SourceID: "reporter-1"}})
	l.Add(Claim{Kind: KindStatic, Subject: pkgSubject, Polarity: PolarityRefutes,
		Provenance: Provenance{SourceID: "reporter-2"}})

	if got := l.IndependentSources(); got != 2 {
		t.Errorf("IndependentSources() = %d, want 2 — two parties did speak", got)
	}
	if got := l.IndependentSupport(pkgSubject); got != 1 {
		t.Errorf("IndependentSupport() = %d, want 1 — the second party disagreed, "+
			"which is not a second reason to believe", got)
	}

	// A retracted supporter stops corroborating.
	l.Claims[1].Polarity = PolaritySupports
	if got := l.IndependentSupport(pkgSubject); got != 2 {
		t.Fatalf("two supporting sources = %d, want 2", got)
	}
	l.Claims[1].Status = StatusRetracted
	if got := l.IndependentSupport(pkgSubject); got != 1 {
		t.Errorf("a retracted observation still corroborated: got %d, want 1", got)
	}
}

// TestCandidateIsASubject pins the eighth kind and, more usefully, the reason
// it exists: a pattern scanner's claims are overwhelmingly about a match at a
// location, and a refuted candidate never becomes a finding — so a model that
// could only speak about findings would lose exactly the reasoning worth
// keeping.
func TestCandidateIsASubject(t *testing.T) {
	c := Subject{Kind: SubjectCandidate, ID: "SEC-240@config/app.go:41:9"}
	if !c.Valid() {
		t.Fatal("a candidate subject did not validate")
	}

	l := &Ledger{}
	l.Add(Claim{
		Kind: KindHeuristic, Subject: c,
		Statement:  "pattern matched a field/separator/value assignment",
		Provenance: Provenance{Source: "nox-scan"},
	})
	if got := l.ConfidenceAbout(c); got != ConfidenceLow {
		t.Errorf("a lone pattern match scored %s, want LOW", got)
	}

	l.Add(Claim{
		Kind: KindStatic, Subject: c, Polarity: PolarityRefutes,
		Statement:  "the match lies entirely within a comment region",
		Provenance: Provenance{Source: "nox-scan"},
	})
	if got := l.ConfidenceAbout(c); got != ConfidenceLow {
		t.Errorf("a refuted candidate scored %s, want LOW", got)
	}
	if l.Len() != 2 {
		t.Error("refuting a candidate discarded the claims; the reasoning is the point")
	}
}

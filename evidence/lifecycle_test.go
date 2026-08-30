package evidence

import "testing"

// TestARetractedClaimWeighsNothingEverywhere is B4's own promise, checked
// against every Ledger accessor rather than the one it was originally wired
// into.
//
// The doc on Status says a retracted claim "weighs nothing, exactly as an
// unrecognised Kind does". When B4 landed, only counted() honoured that —
// Confidence, Conflict and IndependentSupport went through it, and Kinds,
// HasDeterministic, HasSemantic and IndependentSources did not. Nothing caught
// it because nothing in either consumer ever set a Status, so the whole
// lifecycle had never run.
//
// The failure that made it worth fixing rather than documenting: a retracted
// reporter still counted toward IndependentSources, so consensus would survive
// the withdrawal of the belief it was made of.
func TestARetractedClaimWeighsNothingEverywhere(t *testing.T) {
	subject := Subject{Kind: SubjectPackage, ID: "npm/left-pad"}
	live := Claim{
		Kind: KindHeuristic, Statement: "a pattern matched", Subject: subject,
		Provenance: Provenance{Source: "nox", SourceID: "reporter-1"},
	}
	retracted := Claim{
		Kind: KindControlledReproduction, Statement: "the exploit reproduced",
		Subject: subject, Status: StatusRetracted,
		Provenance: Provenance{Source: "nox", SourceID: "reporter-2"},
	}
	l := Ledger{Claims: []Claim{live, retracted}}

	if l.HasDeterministic() {
		t.Error("a retracted reproduction still reports deterministic evidence; a " +
			"withdrawn proof is not a proof")
	}
	if got := l.IndependentSources(); got != 1 {
		t.Errorf("IndependentSources = %d, want 1: a reporter who withdrew their "+
			"observation is not corroborating anything, and counting them lets "+
			"consensus outlive the belief it was made of", got)
	}
	for _, k := range l.Kinds() {
		if k == KindControlledReproduction {
			t.Error("Kinds lists a retracted claim's kind, so a caller reading it as " +
				"'what this ledger establishes' sees evidence that was withdrawn")
		}
	}
	if got, ok := l.StrongestLive(); !ok || got.Kind != KindHeuristic {
		t.Errorf("StrongestLive = %+v (ok=%v), want the heuristic: explaining a verdict "+
			"with a claim that did not contribute to it reads as a bug in the verdict",
			got, ok)
	}
	if got := l.ConfidenceAbout(subject); got != ConfidenceLow {
		t.Errorf("confidence = %s, want LOW; the reproduction was withdrawn", got)
	}

	// The audit trail keeps everything. "We were wrong" is a different
	// statement from "we never said it", and only one of them is honest.
	if l.Len() != 2 {
		t.Errorf("Len = %d, want 2: a retracted claim must stay in the ledger", l.Len())
	}
	if got, ok := l.Strongest(); !ok || got.Kind != KindControlledReproduction {
		t.Errorf("Strongest = %+v (ok=%v); it reports what is IN the ledger, so an "+
			"audit view can still show the withdrawn claim", got, ok)
	}
}

// TestSemanticEvidenceObeysTheSameRule. HasSemantic labels a verdict as partly
// LLM-derived, and a retracted judgment must not carry that label any more than
// a retracted reproduction carries determinism.
func TestSemanticEvidenceObeysTheSameRule(t *testing.T) {
	l := Ledger{Claims: []Claim{{
		Kind: KindSemantic, Statement: "a model judged this exploitable",
		Status: StatusInvalidated,
	}}}
	if l.HasSemantic() {
		t.Error("an invalidated semantic claim still labels the verdict as semantic")
	}
}

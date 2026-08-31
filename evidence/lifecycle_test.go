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

// TestReproducingATriggerDoesNotConfirmAnExploit is the reproduction hierarchy.
//
// Reproducing something is not reproducing everything. An integer overflow that
// fires establishes that the trigger condition holds — not that a security
// invariant was violated, not that the effect is exploitable. Those are
// strictly later propositions with their own evidence.
//
// The failure this prevents is quiet. Every unattributed claim shares the zero
// subject, so a run that attributes nothing puts all its evidence in one bag
// where the cheapest deterministic claim satisfies the precondition for the
// most expensive. core/attack attributed nothing when this was written.
func TestReproducingATriggerDoesNotConfirmAnExploit(t *testing.T) {
	trigger := Subject{Kind: SubjectTriggerCondition, ID: "int-overflow@parse.c:88"}
	exploit := Subject{Kind: SubjectExploit, ID: "rce-via-parse"}

	// The overflow reproduced, deterministically, under a sound control.
	l := &Ledger{Claims: []Claim{{
		Kind: KindControlledReproduction, Subject: trigger,
		Statement:  "the overflow recurred on every sample",
		Provenance: Provenance{Source: "nox-attack"},
	}}}
	outcome := RunOutcome{Executed: true, Violated: true, Reproduced: true, ControlSound: true}

	if got := DeriveExploitabilityAbout(outcome, l, trigger); got != Confirmed {
		t.Errorf("the trigger condition itself did not confirm: %s. The evidence is "+
			"about exactly this proposition and should carry it", got)
	}
	if got := DeriveExploitabilityAbout(outcome, l, exploit); got == Confirmed {
		t.Error("reproducing the trigger condition confirmed the EXPLOIT. A bug " +
			"condition firing is not a security effect and is not an exploit; " +
			"promoting across that gap is how a scanner claims an RCE it never saw")
	}

	// The intermediate propositions are equally not confirmed by it.
	for _, k := range []SubjectKind{SubjectInvariantViolation, SubjectCrash, SubjectSecurityEffect} {
		s := Subject{Kind: k, ID: "same-defect"}
		if got := DeriveExploitabilityAbout(outcome, l, s); got == Confirmed {
			t.Errorf("reproducing the trigger confirmed %s", k)
		}
	}
}

// TestUnattributedEvidenceStillWorks. The zero subject is the old behaviour and
// must stay usable: a producer that types nothing gets what it always got,
// rather than silently losing its verdict.
func TestUnattributedEvidenceStillWorks(t *testing.T) {
	l := &Ledger{Claims: []Claim{{
		Kind: KindControlledReproduction, Statement: "reproduced",
	}}}
	outcome := RunOutcome{Executed: true, Violated: true, Reproduced: true, ControlSound: true}
	if got := DeriveExploitability(outcome, l); got != Confirmed {
		t.Errorf("unattributed evidence no longer confirms: %s", got)
	}
	// And it does not leak into a typed proposition.
	typed := Subject{Kind: SubjectExploit, ID: "x"}
	if got := DeriveExploitabilityAbout(outcome, l, typed); got == Confirmed {
		t.Error("unattributed evidence confirmed a typed proposition it says nothing about")
	}
}

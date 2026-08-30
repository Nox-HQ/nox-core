package evidence

import "sort"

// This file holds the aggregation that became possible once claims carried a
// subject and a polarity: asking what the evidence says about ONE proposition,
// with the reasons against it counted rather than discarded.
//
// Composition ACROSS subjects is deliberately not here. A package being
// affected and a call path being unreachable are both true and neither
// outranks the other; turning them into one verdict requires knowing what the
// consumer is deciding, and that judgement belongs to the consumer.

// Subjects returns every distinct subject the ledger holds claims about,
// sorted for determinism. A ledger whose claims all predate subjects returns
// exactly one entry: the zero Subject.
func (l *Ledger) Subjects() []Subject {
	seen := make(map[Subject]bool, len(l.Claims))
	for _, c := range l.Claims {
		seen[c.Subject] = true
	}
	out := make([]Subject, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Mixed reports whether the ledger holds claims about more than one subject.
//
// A mixed ledger has no single confidence, because the claims in it are not
// about the same thing. Callers building one should key by subject instead;
// callers reading one should use ConfidenceAbout.
func (l *Ledger) Mixed() bool { return len(l.Subjects()) > 1 }

// About returns the sub-ledger of claims concerning s, preserving order.
func (l *Ledger) About(s Subject) Ledger {
	var out Ledger
	for _, c := range l.Claims {
		if c.Subject == s {
			out.Add(c)
		}
	}
	return out
}

// Unauthorized returns the claims a does not permit their producer to assert,
// in ledger order.
//
// These claims are still in the ledger and still visible; they simply carry no
// weight. A producer overreaching is itself a fact worth keeping, and a model
// that deleted the evidence of overreach would be the one place the audit trail
// went quiet exactly when it mattered.
func (l *Ledger) Unauthorized(a Authority) []Claim {
	if !a.Enforcing() {
		return nil
	}
	var out []Claim
	for _, c := range l.Claims {
		if !c.Authorized(a) {
			out = append(out, c)
		}
	}
	return out
}

// counted returns the claims about s that may contribute to a verdict: live,
// of a recognised kind, and permitted by a.
func (l *Ledger) counted(s Subject, a Authority) []Claim {
	var out []Claim
	for _, c := range l.Claims {
		if c.Subject == s && c.Live() && c.Authorized(a) {
			out = append(out, c)
		}
	}
	return out
}

// strongestOf returns the heaviest claim matching want, and whether one exists.
// Ties break on the earlier claim so results are stable under re-evaluation.
func strongestOf(claims []Claim, want func(Claim) bool) (Claim, bool) {
	best := -1
	for i := range claims {
		if !want(claims[i]) {
			continue
		}
		if best < 0 || claims[i].Kind.Strength() > claims[best].Kind.Strength() {
			best = i
		}
	}
	if best < 0 {
		return Claim{}, false
	}
	return claims[best], true
}

// IndependentSupport counts the distinct sources that CORROBORATE the
// proposition about s: live, permitted, supporting claims with an attributed
// SourceID.
//
// It is deliberately a different number from IndependentSources, which counts
// distinct reporters however they weigh in. Both are useful and confusing them
// is a real error, so they are separate methods rather than one with a flag:
//
//   - IndependentSources answers "how many distinct parties have said anything
//     about this?" — an attribution question, and the right input to a
//     disclosure decision about whether a report is a rumour.
//   - IndependentSupport answers "how many distinct parties give us reason to
//     believe it?" — a corroboration question, and the only one that may
//     promote a confidence level.
//
// A second source arriving to REFUTE something is not a second reason to
// believe it, and a retracted observation is not a reason at all.
func (l *Ledger) IndependentSupport(s Subject) int {
	return independentSupport(l.counted(s, Authority{}))
}

// independentSupport counts distinct sources among supporting claims.
func independentSupport(claims []Claim) int {
	seen := make(map[string]bool, len(claims))
	for _, c := range claims {
		if c.Supports() && c.Provenance.SourceID != "" {
			seen[c.Provenance.SourceID] = true
		}
	}
	return len(seen)
}

// ConfidenceAbout aggregates the ledger's claims about one subject into a
// confidence level, counting refutations.
//
// It is ConfidenceUnder with no authority enforcement.
func (l *Ledger) ConfidenceAbout(s Subject) Confidence {
	return l.ConfidenceAboutUnder(s, Authority{})
}

// ConfidenceAboutUnder aggregates the claims about s that a permits.
//
// The rules, in order:
//
//  1. No countable claim about s is LOW. Nothing is not a refutation, and it is
//     not a corroboration either.
//  2. A refutation at least as strong as the best support defeats it, and the
//     result is LOW. The one exception is the rule the whole ladder exists for:
//     a DETERMINISTIC support is not overturned by a non-deterministic
//     refutation, however heavy that refutation's kind happens to weigh. An
//     LLM's disagreement does not unmake a reproduced exploit.
//  3. CONFIRMED still requires a deterministic supporting claim at reproduction
//     strength or above — and now additionally requires that no deterministic
//     refutation of equal or greater strength stands against it.
//  4. Otherwise the level follows the strongest support, promoted one band
//     (capped at HIGH) by two or more independent supporting sources.
//  5. A support consisting only of LLM judgement is capped at MEDIUM.
//
// PolarityUnknown claims are counted as present but argue neither way: they
// keep rule 1 from firing, which is the point. "We looked and could not tell"
// must be distinguishable from "we never looked", and neither may read as a
// refutation.
func (l *Ledger) ConfidenceAboutUnder(s Subject, a Authority) Confidence {
	claims := l.counted(s, a)
	if len(claims) == 0 {
		return ConfidenceLow
	}

	support, hasSupport := strongestOf(claims, Claim.Supports)
	refutation, hasRefutation := strongestOf(claims, Claim.Refutes)

	if hasRefutation {
		if !hasSupport {
			return ConfidenceLow
		}
		overturns := refutation.Kind.Strength() >= support.Kind.Strength()
		protected := support.Kind.Deterministic() && !refutation.Kind.Deterministic()
		if overturns && !protected {
			return ConfidenceLow
		}
	}
	if !hasSupport {
		return ConfidenceLow
	}

	if support.Kind.Deterministic() && support.Kind.Strength() >= strengths[KindControlledReproduction] {
		if !hasRefutation || !refutation.Kind.Deterministic() ||
			refutation.Kind.Strength() < support.Kind.Strength() {
			return ConfidenceConfirmed
		}
	}

	level := levelForStrength(support.Kind.Strength())
	if independentSupport(claims) >= 2 && level.rank() < ConfidenceHigh.rank() {
		level = promote(level)
	}
	if onlySemanticSupport(claims) && level.AtLeast(ConfidenceHigh) {
		level = ConfidenceMedium
	}
	return level
}

// ConfidenceUnder aggregates a single-subject ledger under an authority.
//
// A MIXED ledger returns LOW, because there is no such thing as the confidence
// of a bag of claims about different things — that aggregation is exactly the
// bug typed subjects exist to prevent, and answering it with a number would
// reintroduce it under a new name. Callers holding a mixed ledger want
// ConfidenceAbout per subject, and Mixed reports the case explicitly.
func (l *Ledger) ConfidenceUnder(a Authority) Confidence {
	subjects := l.Subjects()
	if len(subjects) != 1 {
		return ConfidenceLow
	}
	return l.ConfidenceAboutUnder(subjects[0], a)
}

// Conflict reports whether the strongest support and the strongest refutation
// about s are of equal strength — the case where the evidence genuinely does
// not decide, as opposed to deciding against.
//
// It is reported rather than resolved. A conflict silently collapsed to a
// number is a disagreement the operator never sees, and disagreement between
// two producers about one proposition is precisely the thing worth surfacing.
func (l *Ledger) Conflict(s Subject) bool {
	claims := l.counted(s, Authority{})
	support, hasSupport := strongestOf(claims, Claim.Supports)
	refutation, hasRefutation := strongestOf(claims, Claim.Refutes)
	if !hasSupport || !hasRefutation {
		return false
	}
	return support.Kind.Strength() == refutation.Kind.Strength()
}

// onlySemanticSupport reports whether every supporting claim is LLM judgement.
func onlySemanticSupport(claims []Claim) bool {
	found := false
	for _, c := range claims {
		if !c.Supports() {
			continue
		}
		if !c.Kind.Semantic() {
			return false
		}
		found = true
	}
	return found
}

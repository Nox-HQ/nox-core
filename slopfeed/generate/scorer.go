package generate

import (
	"fmt"
	"math"

	"github.com/nox-hq/nox-core/slopfeed"
)

// neighbourBoost lifts the risk of names that are also classic typosquat lures
// (likely-emitted AND a lure). Composition names get no boost.
func neighbourBoost(prior float64, pattern string) float64 {
	switch pattern {
	case "typo":
		return math.Min(1.0, prior+0.08)
	case "obvious":
		return math.Min(1.0, prior+0.04)
	default:
		return prior
	}
}

// Tier buckets a risk score into a feed tier. It returns "" for a score below
// 0.50, which is not likely enough to assert as a predictive target.
func Tier(score float64) string {
	switch {
	case score >= 0.80:
		return slopfeed.TierCritical
	case score >= 0.65:
		return slopfeed.TierHigh
	case score >= 0.50:
		return slopfeed.TierMedium
	default:
		return ""
	}
}

// Score turns a candidate that was re-verified UNREGISTERED into a feed entry.
// It returns ok=false for anything that must not be written: a result that is
// not Unregistered (never accuse a registered package) or a risk below the
// medium tier. verifiedAt is the date the 404 was confirmed, stamped into the
// entry so the claim is time-bound.
func Score(c Candidate, r CheckResult, verifiedAt string) (slopfeed.Entry, bool) {
	if r.Verdict != Unregistered {
		return slopfeed.Entry{}, false
	}
	risk := round3(neighbourBoost(c.Prior, c.Pattern))
	tier := Tier(risk)
	if tier == "" {
		return slopfeed.Entry{}, false
	}
	reason := fmt.Sprintf(
		"UNREGISTERED (404 confirmed twice on %s) and matches a high-likelihood "+
			"hallucination pattern [%s]: %s. An attacker could register this name "+
			"today and capture installs of hallucinated `%s`.",
		verifiedAt, c.Pattern, c.Reason, c.Name,
	)
	return slopfeed.Entry{
		Name:       c.Name,
		Ecosystem:  c.Ecosystem,
		Pattern:    c.Pattern,
		NeighborOf: c.NeighborOf,
		Risk:       risk,
		Tier:       tier,
		Reason:     reason,
		VerifiedAt: verifiedAt,
	}, true
}

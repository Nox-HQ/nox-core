package generate

import (
	"testing"

	"github.com/nox-hq/nox-core/slopfeed"
)

func TestGenerateIsDeterministic(t *testing.T) {
	a := Candidates()
	b := Candidates()
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("generation not deterministic in length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("generation not deterministic at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestGenerateNeverEmitsRealSeed(t *testing.T) {
	// A candidate that collides with a real, popular seed must be dropped — the
	// generator only ever proposes names that are NOT known-real packages.
	realSeeds := map[string]struct{}{}
	for _, n := range pypiSeeds {
		realSeeds["pypi\x00"+n] = struct{}{}
	}
	for _, n := range npmSeeds {
		realSeeds["npm\x00"+n] = struct{}{}
	}
	for _, c := range Candidates() {
		if _, isReal := realSeeds[c.Ecosystem+"\x00"+c.Name]; isReal {
			t.Errorf("candidate collides with a real seed: %s/%s", c.Ecosystem, c.Name)
		}
	}
}

func TestGeneratePriorsInRange(t *testing.T) {
	for _, c := range Candidates() {
		if c.Prior < 0 || c.Prior > 1 {
			t.Errorf("prior out of range for %s: %v", c.Name, c.Prior)
		}
		if c.Ecosystem != "pypi" && c.Ecosystem != "npm" {
			t.Errorf("unexpected ecosystem %q for %s", c.Ecosystem, c.Name)
		}
	}
}

func TestKnownSquattableNamesAreGenerated(t *testing.T) {
	// The names the research verified as squattable must actually be produced by
	// the generator model — otherwise the harness could never have found them.
	want := map[string]string{
		"openai-utils":      "pypi",
		"anthropic-async":   "pypi",
		"axios-retry-async": "npm",
		"numpys":            "pypi",
		"requests-sdk":      "pypi",
	}
	got := map[string]string{}
	for _, c := range Candidates() {
		got[c.Name] = c.Ecosystem
	}
	for name, eco := range want {
		if got[name] != eco {
			t.Errorf("expected generator to produce %s (%s); it did not", name, eco)
		}
	}
}

func TestScoreSquattableProducesValidFeedEntry(t *testing.T) {
	c := Candidate{Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious", Prior: 0.78, Reason: "obvious API name"}
	r := CheckResult{Name: c.Name, Ecosystem: c.Ecosystem, Verdict: Unregistered}
	e, ok := Score(c, r, "2026-07-25")
	if !ok {
		t.Fatal("expected an unregistered high-prior candidate to score squattable")
	}
	if e.Tier != slopfeed.TierCritical && e.Tier != slopfeed.TierHigh && e.Tier != slopfeed.TierMedium {
		t.Errorf("unexpected tier %q", e.Tier)
	}
	if e.VerifiedAt != "2026-07-25" {
		t.Errorf("verified_at not stamped: %q", e.VerifiedAt)
	}
}

func TestLowRiskCandidateNotWritten(t *testing.T) {
	// A composition name with a low prior falls below the medium tier and must
	// not be written to the feed even when unregistered.
	c := Candidate{Name: "requests-x", Ecosystem: "pypi", Pattern: "composition", Prior: 0.40}
	r := CheckResult{Verdict: Unregistered}
	if _, ok := Score(c, r, "2026-07-25"); ok {
		t.Fatal("a sub-medium-risk candidate must not be written to the feed")
	}
}

package evidence

import (
	"errors"
	"strings"
	"testing"
)

func validReport() RunReport {
	return RunReport{
		SchemaVersion: RunReportSchema, Fingerprint: strings.Repeat("a", 64),
		Exploitability: Confirmed, Kind: KindDynamicExploit,
		Deterministic: true, Reproduced: true, ControlSound: true, Samples: 3, Hits: 3,
		Profile: "sandbox", TraceDigest: strings.Repeat("b", 64),
		Tool: "nox", Version: "1.50.0", ObservedAt: "2026-10-26T10:00:00Z",
	}
}

func TestRunReport_ValidAccepted(t *testing.T) {
	r := validReport()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if !r.Establishes() || r.Strength() != 95 {
		t.Fatalf("establishes=%v strength=%d", r.Establishes(), r.Strength())
	}
}

func TestRunReport_Refusals(t *testing.T) {
	cases := map[string]func(*RunReport){
		"schema":            func(r *RunReport) { r.SchemaVersion = 2 },
		"fingerprint":       func(r *RunReport) { r.Fingerprint = "xyz" },
		"state":             func(r *RunReport) { r.Exploitability = "PWNED" },
		"unknown kind":      func(r *RunReport) { r.Kind = "vibes" },
		"claim kind":        func(r *RunReport) { r.Kind = ReportedRunKind },
		"maintainer kind":   func(r *RunReport) { r.Kind = KindMaintainerConfirmed },
		"safe profile":      func(r *RunReport) { r.Profile = "safe" },
		"digest":            func(r *RunReport) { r.TraceDigest = "http://target/trace" },
		"hits>samples":      func(r *RunReport) { r.Hits = 4 },
		"huge samples":      func(r *RunReport) { r.Samples = MaxRunSamples + 1 },
		"tool is a url":     func(r *RunReport) { r.Tool = "https://x" },
		"version is a path": func(r *RunReport) { r.Version = "/etc/passwd" },
		"time":              func(r *RunReport) { r.ObservedAt = "yesterday" },
		"confirmed by llm":  func(r *RunReport) { r.Kind = KindSemantic },
		"confirmed no oracle": func(r *RunReport) {
			r.Deterministic = false
		},
		"confirmed unreproduced": func(r *RunReport) { r.Reproduced = false },
		"confirmed no control":   func(r *RunReport) { r.ControlSound = false },
		"confirmed by static":    func(r *RunReport) { r.Kind = KindStatic },
	}
	for name, mut := range cases {
		r := validReport()
		mut(&r)
		err := r.Validate()
		if err == nil || !errors.Is(err, ErrRunReportInvalid) {
			t.Errorf("%s: want ErrRunReportInvalid, got %v", name, err)
		}
	}
}

func TestRunReport_NonConfirmedStatesAreReportable(t *testing.T) {
	for _, s := range []Exploitability{Prevented, Inconclusive, Plausible} {
		r := validReport()
		r.Exploitability, r.Kind, r.Deterministic, r.Reproduced, r.Hits = s, KindHeuristic, false, false, 0
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", s, err)
		}
		if r.Establishes() {
			t.Errorf("%s must not establish", s)
		}
	}
}

// The structural guarantee: a ledger of reporter-scoped runs, however many and
// however strong, never raises confidence and never confirms.
func TestRunReportClaim_NeverLiveNeverConfirms(t *testing.T) {
	var base, with Ledger
	base.Add(Claim{Kind: KindStatic, Statement: "taint path", Provenance: Provenance{Source: "nox-scan"}})
	with.Claims = append(with.Claims, base.Claims...)
	for i := 0; i < 50; i++ {
		r := validReport()
		with.Add(r.Claim("nox-intel-attack", strings.Repeat(string(rune('a'+i%26)), 8)+string(rune('0'+i%10))))
	}
	for _, c := range with.Claims[1:] {
		if c.Live() || c.Kind.Strength() != 0 {
			t.Fatalf("reporter-scoped claim must weigh nothing: live=%v", c.Live())
		}
	}
	if got, want := with.Confidence(), base.Confidence(); got != want {
		t.Fatalf("50 reported runs moved confidence %s -> %s", want, got)
	}
	if with.Confidence() == ConfidenceConfirmed {
		t.Fatal("reported runs reached CONFIRMED")
	}
	// Even alone.
	var only Ledger
	only.Add(validReport().Claim("nox-intel-attack", "r1"))
	if only.Confidence() == ConfidenceConfirmed || only.IndependentSources() != 0 {
		t.Fatalf("a lone reported run: confidence=%s sources=%d", only.Confidence(), only.IndependentSources())
	}
}

func TestRunReportClaim_CarriesProvenance(t *testing.T) {
	c := validReport().Claim("nox-intel-attack", "att_1")
	if c.Provenance.Reference != strings.Repeat("b", 64) || c.Provenance.SourceID != "att_1" ||
		c.Attributes[AttrScope] != ScopeReporter || c.Attributes[AttrReportedStrength] != "95" {
		t.Fatalf("%+v", c)
	}
}

func TestConfirmedByIsTheOneRule(t *testing.T) {
	type c struct {
		k            Kind
		det, rep, ok bool
		want         bool
	}
	for i, tc := range []c{
		{KindDynamicExploit, true, true, true, true},
		{KindControlledReproduction, true, true, true, true},
		{KindDynamicExploit, true, true, false, false}, // control tripped
		{KindDynamicExploit, true, false, true, false}, // did not reproduce
		{KindDynamicExploit, false, true, true, false}, // not deterministic
		{KindSourceConfirmed, true, true, true, false}, // below reproduction strength
		{KindSemantic, true, true, true, false},        // judgment
		{KindStatic, true, true, true, false},
		{KindMaintainerConfirmed, true, true, true, true}, // strong and deterministic kind
	} {
		if got := ConfirmedBy(tc.k, tc.det, tc.rep, tc.ok); got != tc.want {
			t.Errorf("case %d %+v: got %v", i, tc, got)
		}
	}
	if QualifiesAsReproduction(KindHeuristic, true) {
		t.Error("a heuristic qualified as a reproduction")
	}
}

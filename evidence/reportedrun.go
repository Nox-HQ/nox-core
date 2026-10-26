package evidence

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RunReport is the wire form of one `nox attack` run that a reporter's own CI
// contributes to an intelligence service.
//
// It is shared here so the producer (the CLI) and the consumer (the service)
// cannot drift on what may cross the boundary, and so the rule that governs it
// has one definition:
//
//	reporter-scoped evidence is never trusted beyond the reporter that sent it.
//
// The struct IS the allowlist. There is no target URL, host, route, payload,
// response body or free text field; the run is identified by a digest of its
// trace, which the reporter can produce again from the trace they keep and
// nobody else can reconstruct. A field that is not declared cannot be sent, and
// a decoder that rejects unknown fields (the service's does) refuses one.
//
// What a report carries is the evidence model's own vocabulary: the Kind the
// run's evidence has (and so its Strength, derived rather than sent), the
// Exploitability the run reached, whether an oracle decided it
// deterministically and whether it reproduced, and provenance (tool, version,
// time). Nothing here is a verdict about the vulnerability in general; it is
// one reporter's account of one run against one target the reporter controls.
type RunReport struct {
	// SchemaVersion is RunReportSchema.
	SchemaVersion int `json:"schema_version"`
	// Fingerprint is the intelligence candidate the reporter says the run
	// exercised (64 lowercase hex). It is the reporter's statement: an attack is
	// grounded in the reporter's findings, not in intelligence.
	Fingerprint string `json:"fingerprint"`
	// Exploitability is the state the run reached on this package's scale.
	Exploitability Exploitability `json:"exploitability"`
	// Kind is how the run's evidence was established. Its Strength is derived
	// from it by Strength, never sent.
	Kind Kind `json:"kind"`
	// Deterministic is true when a machine-checkable oracle decided the run.
	Deterministic bool `json:"deterministic"`
	// Reproduced is true when the violation recurred under the determinism gate.
	Reproduced bool `json:"reproduced"`
	// ControlSound is true when the run's benign control stayed clean, i.e. the
	// environment could tell obedience from noise. CONFIRMED is meaningless
	// without it, so Validate demands it, as the service's own derivation does.
	ControlSound bool `json:"control_sound"`
	// Samples and Hits are the determinism gate's denominator and numerator.
	Samples int `json:"samples"`
	Hits    int `json:"hits"`
	// Profile is the safety profile the run used: safe, sandbox, staging or
	// authorized-live. A safe run sends nothing, so it can never have observed
	// anything and is refused as evidence of exploitation.
	Profile string `json:"profile"`
	// TraceDigest is the hex SHA-256 of the run's recorded trace. It is the
	// citation: it lets the reporter, and only the reporter, show which run a
	// claim was about.
	TraceDigest string `json:"trace_digest"`
	// Tool and Version identify the producing build; ObservedAt is RFC3339.
	Tool       string `json:"tool,omitempty"`
	Version    string `json:"version,omitempty"`
	ObservedAt string `json:"observed_at"`
}

// RunReportSchema is the wire version of RunReport.
const RunReportSchema = 1

// ReportedRunKind is the Kind of the ledger claim a RunReport becomes.
//
// It is deliberately NOT one of the recognised kinds: Claim.Live requires a
// recognised kind and Kind.Strength of an unrecognised one is 0, so a ledger
// holding any number of these keeps them in the audit trail, attributes them to
// the reporter, and weighs them at nothing. That is the structural reason a
// reporter's run cannot lift a shared candidate's confidence, let alone to
// CONFIRMED, however many reporters there are or how strong the run was. Only a
// consumer that has verified a run itself may record it as KindDynamicExploit.
const ReportedRunKind Kind = "reported_attack_run"

// Attribute keys a RunReport claim carries.
const (
	AttrReportedKind           = "reported_kind"
	AttrReportedStrength       = "reported_strength"
	AttrReportedExploitability = "reported_exploitability"
	AttrReportedDeterministic  = "reported_deterministic"
	AttrReportedReproduced     = "reported_reproduced"
	AttrReportedControlSound   = "reported_control_sound"
	AttrTraceDigest            = "trace_digest"
	AttrReportedProfile        = "profile"
	// AttrScope marks the claim as reporter-scoped.
	AttrScope = "scope"
	// ScopeReporter is its only value.
	ScopeReporter = "reporter"
)

// RunReport errors.
var (
	// ErrRunReportInvalid wraps every refusal Validate makes.
	ErrRunReportInvalid = errors.New("invalid run report")
)

var (
	fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestRE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRE     = regexp.MustCompile(`^(dev|v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)*(\+[0-9A-Za-z.]+)*)$`)
	toolRE        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// reportableProfiles are the safety profiles whose runs exercised a target.
var reportableProfiles = map[string]bool{"sandbox": true, "staging": true, "authorized-live": true}

// MaxRunSamples bounds Samples, so a report cannot be made to look like a very
// large experiment.
const MaxRunSamples = 1000

// Validate refuses a report that is malformed, inconsistent with the evidence
// model, or carries anything the allowlist does not permit.
func (r RunReport) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrRunReportInvalid, fmt.Sprintf(format, a...))
	}
	if r.SchemaVersion != RunReportSchema {
		return bad("schema_version must be %d", RunReportSchema)
	}
	if !fingerprintRE.MatchString(r.Fingerprint) {
		return bad("fingerprint must be 64 lowercase hex characters")
	}
	if !r.Exploitability.Valid() {
		return bad("exploitability %q is not a defined state", r.Exploitability)
	}
	if !r.Kind.Valid() {
		return bad("kind %q is not a defined evidence kind", r.Kind)
	}
	if !ReporterMayAssert(r.Kind) {
		return bad("kind %q is another party's to give (a maintainer, an advisory, a source read)", r.Kind)
	}
	if r.Kind == ReportedRunKind {
		return bad("kind must be the kind of the run's own evidence, not %q", ReportedRunKind)
	}
	if !reportableProfiles[r.Profile] {
		return bad("profile must be sandbox, staging or authorized-live; a safe run sends nothing and observed nothing")
	}
	if !digestRE.MatchString(r.TraceDigest) {
		return bad("trace_digest must be 64 lowercase hex characters (SHA-256 of the trace)")
	}
	if r.Samples < 0 || r.Samples > MaxRunSamples || r.Hits < 0 || r.Hits > r.Samples {
		return bad("hits must be between 0 and samples, and samples at most %d", MaxRunSamples)
	}
	if r.Tool != "" && !toolRE.MatchString(r.Tool) {
		return bad("tool must be a lowercase name")
	}
	if r.Version != "" && (len(r.Version) > 64 || !versionRE.MatchString(r.Version)) {
		return bad("version must be \"dev\" or a version such as 1.50.0")
	}
	if _, err := time.Parse(time.RFC3339, r.ObservedAt); err != nil {
		return bad("observed_at must be RFC3339")
	}
	// The consistency the evidence model itself demands: CONFIRMED is never a
	// matter of what a reporter calls it. One rule, ConfirmedBy, shared with every
	// consumer that derives a verdict from a claimed run.
	if r.Exploitability == Confirmed && !ConfirmedBy(r.Kind, r.Deterministic, r.Reproduced, r.ControlSound) {
		return bad("CONFIRMED needs a deterministic evidence kind at reproduction strength or above "+
			"(got %q, strength %d), a deterministic oracle, a reproduction and a sound benign control", r.Kind, r.Kind.Strength())
	}
	for _, s := range []string{r.Tool, r.Version} {
		if strings.Contains(s, "://") || strings.ContainsAny(s, "/\\") {
			return bad("provenance fields carry names, never locations")
		}
	}
	return nil
}

// ReproductionStrength is the weakest evidence strength that counts as a
// reproduction.
var ReproductionStrength = KindControlledReproduction.Strength()

// QualifiesAsReproduction reports whether a claimed run's evidence is of a kind
// that can back CONFIRMED: a deterministic kind at reproduction strength or
// above, with a deterministic oracle behind it. A bare "deterministic: true" on
// a heuristic or semantic kind is a claim of determinism, not evidence of it.
func QualifiesAsReproduction(kind Kind, deterministic bool) bool {
	return deterministic && kind.Deterministic() && kind.Strength() >= ReproductionStrength
}

// ConfirmedBy is the single definition of when a CLAIMED run may be read as
// CONFIRMED: qualifying evidence (QualifiesAsReproduction), a violation that
// reproduced, and a sound benign control. Producers validate with it and the
// service's derivation builds on QualifiesAsReproduction, so the rule is stated
// once.
func ConfirmedBy(kind Kind, deterministic, reproduced, controlSound bool) bool {
	return QualifiesAsReproduction(kind, deterministic) && reproduced && controlSound
}

// Strength is the 0-100 weight the run's own evidence kind carries at the
// reporter. It is derived, and it applies to the reporter's view only: see
// ReportedRunKind for why it weighs nothing in a shared ledger.
func (r RunReport) Strength() int { return r.Kind.Strength() }

// Establishes reports whether the report claims an observed violation that a
// deterministic oracle decided and that reproduced. It is a claim about the
// reporter's run, not a verdict about the vulnerability.
func (r RunReport) Establishes() bool {
	return r.Exploitability == Confirmed && r.Deterministic && r.Reproduced
}

// Claim renders the report as a ledger claim attributed to sourceID under
// source. Its Kind is ReportedRunKind, so the claim is recorded and attributed
// and weighs nothing; the reporter's own view reads the attributes.
func (r RunReport) Claim(source, sourceID string) Claim {
	return Claim{
		Kind: ReportedRunKind,
		Statement: "a reporter's own nox attack run reached " + string(r.Exploitability) +
			" (reporter-scoped; not verified by this service)",
		Provenance: Provenance{
			Source:     source,
			SourceID:   sourceID,
			Tool:       r.Tool,
			Version:    r.Version,
			ObservedAt: r.ObservedAt,
			Reference:  r.TraceDigest,
		},
		Attributes: map[string]string{
			AttrScope:                  ScopeReporter,
			AttrReportedKind:           string(r.Kind),
			AttrReportedStrength:       strconv.Itoa(r.Strength()),
			AttrReportedExploitability: string(r.Exploitability),
			AttrReportedDeterministic:  strconv.FormatBool(r.Deterministic),
			AttrReportedReproduced:     strconv.FormatBool(r.Reproduced),
			AttrReportedControlSound:   strconv.FormatBool(r.ControlSound),
			AttrTraceDigest:            r.TraceDigest,
			AttrReportedProfile:        r.Profile,
		},
	}
}

// ReporterMayAssert reports whether a reporter may claim evidence of this kind
// about its own run. A run it reproduced may be a controlled reproduction or a
// dynamic exploit; a maintainer's word, a published advisory or a source read
// are other parties' to give.
func ReporterMayAssert(k Kind) bool {
	switch k {
	case KindHeuristic, KindSemantic, KindStatic, KindControlledReproduction, KindDynamicExploit:
		return true
	}
	return false
}

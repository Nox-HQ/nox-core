// Package vulnsource is the seam between nox's dependency analysis and whatever
// answers the question "is this package version known to be vulnerable?".
//
// Nox has always asked that question over the network — core/analyzers/deps has
// queried api.osv.dev by default since dependency scanning existed. What keeps
// nox offline-first is not the absence of network code but three properties
// this package is built to preserve:
//
//  1. the capability is switchable off;
//  2. a failed lookup degrades loudly, never into a silent clean scan;
//  3. nothing downstream depends on a source having answered.
//
// A Source implementation owns its own wire protocol entirely. Batching limits,
// ecosystem vocabularies, detail hydration, and the quirks of a particular API
// are implementation business; this package defines only the semantic contract.
//
// # Record shape
//
// Record is deliberately OSV-wire-compatible, json tags included. OSV's schema
// is the interchange baseline every source must be able to speak, which is what
// makes a richer source verifiable against a reference one rather than merely
// asserted to be a superset of it. Sources with more to say extend Record; they
// do not reshape it.
package vulnsource

import (
	"context"
	"time"
)

// Query is one package to look up. Ecosystem is nox's own internal ecosystem
// name ("go", "npm", "pypi", ...); mapping it to a wire vocabulary belongs to
// the implementation, which alone knows what its API accepts.
type Query struct {
	Ecosystem string
	Name      string
	Version   string
}

// Record is a single hydrated vulnerability.
//
// "Hydrated" is part of the contract, not an implementation detail. OSV's batch
// endpoint answers only {id, modified}; a source that returned those directly
// would report every dependency finding at SeverityMedium with an empty
// summary, and since enforcing gates key on high/critical, a critical CVE could
// never block a build. A Source returns records whose severity and affected
// ranges are populated, or it degrades and says so.
type Record struct {
	ID string `json:"id"`

	// Modified is the source database's own last-changed stamp for this
	// advisory, as an RFC3339 timestamp. OSV returns it from both the batch and
	// the detail endpoint.
	//
	// It is the advisory's version, which makes it the only honest cache
	// validator: an advisory document may be reused for exactly as long as this
	// value is unchanged, and must be refetched the moment it moves. Caching a
	// vulnerability database on a guessed TTL trades freshness for speed and
	// hides the trade; keying on the publisher's own stamp does not trade
	// anything.
	Modified string `json:"modified,omitempty"`

	// Published is when the source database first published the advisory (RFC3339).
	// It is the fallback the verifier dates a record by when Modified is absent.
	Published string `json:"published,omitempty"`

	// Withdrawn is set when the source database has retracted the advisory,
	// as an RFC3339 timestamp. A withdrawn advisory is not a vulnerability.
	//
	// OSV's query API excludes these; its bulk export does not. A mirror built
	// from the export therefore has to filter them itself, and a mirror that
	// forgets adds false positives to every scan — which is how this field came
	// to exist: two withdrawn npm advisories surfaced as mirror-only drift on
	// the first production sync.
	Withdrawn string `json:"withdrawn,omitempty"`

	Summary  string     `json:"summary"`
	Details  string     `json:"details"`
	Aliases  []string   `json:"aliases"`
	Severity []Severity `json:"severity"`
	Affected []Affected `json:"affected"`

	// DatabaseSpecific carries source-database annotations. GitHub advisories
	// publish a coarse severity label here, which is the only severity signal
	// available for records that carry a CVSS v4 vector and nothing else.
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`

	// Intelligence is what a source knows beyond the advisory: epistemic
	// status, corroboration across distinct reporters, and the evidence ledger
	// behind it. Nil for a plain advisory database, which is the honest
	// representation — OSV makes no such claims.
	//
	// It is namespaced under nox_intelligence so a record round-trips through
	// the OSV wire format without colliding with anything OSV may add.
	Intelligence *Intelligence `json:"nox_intelligence,omitempty"`

	// Provenance says which upstream each retrieval of this record came from,
	// how it was obtained (live, mirror, candidate) and when. Sent by NOX
	// Intelligence as nox_provenance; absent from a plain OSV.dev response and
	// then nil. It adds information and never changes what the record says.
	Provenance []Provenance `json:"nox_provenance,omitempty"`

	// SameAs lists other records in the same answer that name the same
	// vulnerability under a different identifier (nox_same_as). The service
	// merges nothing, so both records arrive; this is the hint that lets a
	// consumer count them once.
	SameAs []string `json:"nox_same_as,omitempty"`

	// Disagreement lists how the live and mirrored copies of this record
	// differ, when they do (nox_disagreement).
	Disagreement []string `json:"nox_disagreement,omitempty"`

	// Symbols is affected-symbol intelligence (nox_symbols): the functions the
	// advisory's publisher listed, or that its fix changed. Absent from a plain
	// OSV.dev response. See AffectedSymbols for what it may and may not be used
	// to conclude.
	Symbols []AffectedSymbols `json:"nox_symbols,omitempty"`
}

// Provenance is one retrieval of an advisory: the upstream database, the path
// by which the source obtained it, and when.
type Provenance struct {
	// Source is the upstream database, e.g. "osv.dev".
	Source string `json:"source"`
	// Via is "live", "mirror" or "candidate". Unknown values are kept as sent.
	Via string `json:"via"`
	// RetrievedAt is when the retrieval happened (RFC 3339), if known.
	RetrievedAt string `json:"retrieved_at,omitempty"`
	// Modified is the upstream's own last-changed stamp on that version.
	Modified string `json:"modified,omitempty"`
}

// Status returns the record's epistemic standing, resolving a record with no
// intelligence block to PUBLISHED — which is what an advisory database returns.
func (r *Record) Status() Status {
	if r.Intelligence == nil {
		return StatusPublished
	}
	return r.Intelligence.Status.EffectiveStatus()
}

// Theoretical reports whether the record describes an undemonstrated path.
func (r *Record) Theoretical() bool { return r.Intelligence.Theoretical() }

// DatabaseSpecific holds the subset of source-specific annotations nox reads.
type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

// Severity holds a CVSS or other severity score.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Package identifies a package by name and ecosystem, in wire vocabulary.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Affected describes packages and version ranges affected by a vulnerability.
type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
	// Versions is OSV's explicit list of affected versions. OSV decides a
	// package query from this list together with the SEMVER and ECOSYSTEM
	// ranges; many advisories (Hex, malware reports, GIT-ranged entries) carry
	// only this list. See Record.Decide.
	Versions          []string          `json:"versions,omitempty"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

// EcosystemSpecific carries per-ecosystem detail. For Go, advisories are scoped
// to the import paths they actually affect — a module-level match alone
// overstates exposure (e.g. GO-2026-5932 affects only x/crypto/openpgp, not
// every consumer of x/crypto). Dropping this field does not lose a finding; it
// silently inflates the severity of one that should have been demoted.
type EcosystemSpecific struct {
	Imports []Import `json:"imports"`
}

// Import is a single affected import path within a module.
type Import struct {
	Path string `json:"path"`
	// Symbols are the functions within Path the publisher lists as affected
	// (OSV ecosystem_specific.imports[].symbols). Empty means the advisory names
	// the package and not the functions, which says nothing about which are safe.
	Symbols []string `json:"symbols,omitempty"`
}

// Range is a version range with events marking introduction / fix.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is a single point in a version range. Either Introduced or Fixed (or
// LastAffected) is populated; the others are empty.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Source resolves package queries to known vulnerabilities.
//
// Lookup is batch-shaped on purpose. A per-package Lookup(ecosystem, pkg,
// version) reads more naturally but discards the batching real vulnerability
// APIs are built around — OSV accepts 1000 queries per request — turning one
// round trip into one per dependency.
//
// The returned map is keyed by the caller's index into qs, so a source is free
// to skip queries it cannot serve without the caller losing track of which
// answer belongs to which package. Indices absent from the map mean "no
// vulnerabilities", which is why a source that could not complete a lookup must
// record a degradation rather than return an empty map and let it read as
// clean.
//
// A returned error means the lookup could not be attempted at all. Failures
// that are expected in normal operation — an unreachable network, a rejected
// request — are degradations, not errors: they return partial results so a scan
// keeps whatever it did learn.
type Source interface {
	// Name identifies the source in degradation records and provenance.
	Name() string

	// Lookup resolves qs to hydrated records, keyed by index into qs.
	Lookup(ctx context.Context, qs []Query) (map[int][]Record, error)
}

// PartialReporter is an optional interface for a Source that can say which
// queries of its most recent Lookup it answered incompletely. A verifier uses it
// to tell a truncated answer from a withheld one: records the reference adds
// for a partial query are restored, but not counted as suppression. Sources that
// do not implement it are verified exactly as before.
type PartialReporter interface {
	PartialQueries() map[int]struct{}
}

// MirrorSyncReporter is an optional interface for a Source that can answer
// completely from a local mirror of its reference database. It returns, for the
// queries of its most recent Lookup answered complete-from-mirror, when that
// mirror last synced. A verifier uses it to tell lag from withholding: a
// reference record changed after the sync cannot be in the mirror, so its
// absence is expected rather than evidence of suppression. A query absent from
// the map, or mapped to the zero time, has no such excuse.
type MirrorSyncReporter interface {
	MirrorSyncedAt() map[int]time.Time
}

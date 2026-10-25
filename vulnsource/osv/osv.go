// Package osv implements vulnsource.Source against the OSV.dev API.
//
// Everything in here is an OSV wire artifact: batch size limits, the ecosystem
// vocabulary, the two-step query-then-hydrate protocol, and the failure modes
// peculiar to that API. None of it is visible through the vulnsource.Source
// interface, which is the point — a different source answering the same
// question should not have to reproduce OSV's protocol to be substitutable.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
)

// DefaultBaseURL is the public OSV.dev API endpoint.
const DefaultBaseURL = "https://api.osv.dev"

// batchLimit is the maximum number of queries per OSV batch request.
const batchLimit = 1000

// batchConcurrency is how many batch requests are in flight at once.
const batchConcurrency = 4

// hydrateConcurrency bounds in-flight detail lookups so a large dependency tree
// does not open hundreds of simultaneous connections to OSV.
const hydrateConcurrency = 8

// The batch wire types are exported deliberately. OSV's protocol is the
// interchange baseline any nox vulnerability source must be able to speak, so a
// server implementing it — or a test standing in for one — shares these
// definitions rather than restating them and drifting.

// Query is a single package query for the OSV batch API.
type Query struct {
	Package vulnsource.Package `json:"package"`
	Version string             `json:"version"`
}

// BatchRequest is the request body for POST /v1/querybatch.
type BatchRequest struct {
	Queries []Query `json:"queries"`
}

// BatchResponse is the response from the OSV batch endpoint.
type BatchResponse struct {
	Results []BatchResult `json:"results"`
}

// BatchResult holds vulnerabilities for a single query.
type BatchResult struct {
	Vulns []vulnsource.Record `json:"vulns"`

	// Coverage is NOX Intelligence's statement of how completely this query was
	// checked, carried on the wire as nox_coverage. OSV.dev does not send it, so
	// it is nil for a plain OSV response; a nil Coverage is "unreported", which
	// is not the same as "complete" (see Completeness).
	Coverage *Coverage `json:"nox_coverage,omitempty"`
}

// CoverageStatus says how much of the reference database one query was checked
// against. The values are the service's wire vocabulary.
type CoverageStatus string

const (
	// CoverageComplete means the service answered the query in full.
	CoverageComplete CoverageStatus = "complete"
	// CoverageIncomplete means the answer is partial: the advisories returned
	// are real, there may be more.
	CoverageIncomplete CoverageStatus = "incomplete"
	// CoverageUnsupported means the service never asked its reference, because
	// it has no vocabulary for the query's ecosystem.
	CoverageUnsupported CoverageStatus = "unsupported"
	// CoverageDegraded means the answer was assembled from fewer sources than a
	// full one (Coverage.Missing names them). The advisories returned are real.
	CoverageDegraded CoverageStatus = "degraded"
	// CoverageUnavailable means no source could answer the query; an empty list
	// for it is not "no advisories".
	CoverageUnavailable CoverageStatus = "unavailable"
)

// Sources a Coverage can report as not consulted (Coverage.Missing).
const (
	MissingOSVLive       = "osv_live"
	MissingNoxCandidates = "nox_candidates"
)

// Coverage is the per-query completeness statement (nox_coverage).
type Coverage struct {
	Status CoverageStatus `json:"status"`
	Reason string         `json:"reason,omitempty"`

	// Missing names the sources the service did not consult for this query
	// (MissingOSVLive, MissingNoxCandidates). Unknown names are kept.
	Missing []string `json:"missing,omitempty"`
	// Source, with Status degraded, says where the advisories came from when it
	// was not the usual path: "mirror" is the service's local corpus.
	Source string `json:"source,omitempty"`
	// MirrorSyncedAt is when that corpus last synced (RFC 3339).
	MirrorSyncedAt string `json:"mirror_synced_at,omitempty"`
}

// MirrorOnlyNote is the phrase an intel_incomplete degradation's Detail carries
// for a query answered from the service's mirror because live OSV was not
// consulted. It is exported so a consumer can recognise that case by the
// definition rather than by a copy of the sentence.
const MirrorOnlyNote = "answered from the mirror only; live OSV was not consulted"

// fromMirror reports whether the advisories came from the service's mirror
// because live OSV was not consulted.
func (c Coverage) fromMirror() bool {
	return c.Source == "mirror" || c.missing(MissingOSVLive)
}

func (c Coverage) missing(name string) bool {
	for _, m := range c.Missing {
		if m == name {
			return true
		}
	}
	return false
}

// Completeness is a reading of a BatchResult's coverage that keeps "the source
// said complete" apart from "the source said nothing".
type Completeness int

const (
	// Unreported means the response carried no coverage statement, as every
	// plain OSV.dev response does. Nothing was claimed either way, so callers
	// must not read it as an explicit "complete" — and need not treat it as a
	// failure, or every OSV.dev scan would be one.
	Unreported Completeness = iota
	// Complete means the service explicitly said the answer is exhaustive.
	Complete
	// Partial means the service said the answer is not exhaustive, or said
	// something this client does not understand. An unknown status fails
	// closed: a status added later must not be read as a clean answer.
	Partial
)

// Completeness reports what this result says about its own completeness.
// An empty status inside a present nox_coverage object is a malformed
// statement and reads as Partial, not Unreported.
func (r BatchResult) Completeness() Completeness {
	switch {
	case r.Coverage == nil:
		return Unreported
	case r.Coverage.Status == CoverageComplete:
		return Complete
	default:
		return Partial
	}
}

// partialReason renders why a Partial result is partial, for a degradation. It
// names what was not consulted, so "degraded" is never left to be guessed at.
func (c Coverage) partialReason() string {
	reason := string(c.Status)
	if reason == "" {
		reason = "unspecified"
	}
	var notes []string
	if c.Reason != "" {
		notes = append(notes, c.Reason)
	}
	if c.fromMirror() {
		note := MirrorOnlyNote
		if c.MirrorSyncedAt != "" {
			note += " (mirror synced " + c.MirrorSyncedAt + ")"
		}
		notes = append(notes, note)
	}
	if c.missing(MissingNoxCandidates) {
		notes = append(notes, "NOX candidate store was not consulted")
	}
	for _, m := range c.Missing {
		if m != MissingOSVLive && m != MissingNoxCandidates {
			notes = append(notes, "not consulted: "+m)
		}
	}
	if len(notes) > 0 {
		reason += ": " + strings.Join(notes, "; ")
	}
	return reason
}

// Source queries an OSV-wire-protocol endpoint for known vulnerabilities.
type Source struct {
	name    string
	baseURL string
	client  *http.Client
	deg     *degrade.Degradations
	cache   AdvisoryCache

	// acceptDegraded sends X-Nox-Accept-Degraded: mirror on batch lookups.
	acceptDegraded bool

	// partial holds the query indices the most recent Lookup was told were
	// answered incompletely. It is shared by copies made with WithCache.
	partial *partialIndex
}

// partialIndex is the mutex-guarded set behind PartialQueries.
type partialIndex struct {
	mu  sync.Mutex
	set map[int]struct{}
}

// PartialQueries returns the indices (into the slice passed to the most recent
// Lookup) of queries the service said it answered incompletely. It implements
// vulnsource.PartialReporter, which lets a verifier tell truncation from
// withholding.
func (s *Source) PartialQueries() map[int]struct{} {
	out := make(map[int]struct{})
	s.partial.mu.Lock()
	defer s.partial.mu.Unlock()
	for i := range s.partial.set {
		out[i] = struct{}{}
	}
	return out
}

// WithCache returns a copy of the source that serves advisory detail from c.
//
// Only detail is cached. The batch query stays live on every lookup, so which
// advisories match a package version is always answered by upstream and a
// newly published CVE is never hidden behind a cache.
func (s *Source) WithCache(c AdvisoryCache) *Source {
	out := *s
	out.cache = c
	return &out
}

// AcceptDegradedHeader is the request header by which a client tells NOX
// Intelligence it reads nox_coverage and will take a mirror-backed answer,
// marked degraded, when live OSV is down. Without it the service answers 503.
const (
	AcceptDegradedHeader = "X-Nox-Accept-Degraded"
	AcceptDegradedMirror = "mirror"
)

// WithAcceptDegraded returns a copy that opts in to NOX Intelligence's
// mirror-backed fallback. It is for the NOX Intelligence source only: OSV.dev
// does not know the header, and a source that sent it without reading
// nox_coverage would be taking a weaker answer for a complete one. This
// source does read it — a degraded or unavailable query is recorded as an
// intel_incomplete degradation, never as a clean result.
func (s *Source) WithAcceptDegraded() *Source {
	out := *s
	out.acceptDegraded = true
	return &out
}

// New returns a Source querying baseURL through client, named "osv.dev". deg
// may be nil, in which case degradation records are discarded — library callers
// that supply no collector behave exactly as they did before.
func New(baseURL string, client *http.Client, deg *degrade.Degradations) *Source {
	return NewNamed("osv.dev", baseURL, client, deg)
}

// NewNamed returns a Source under a caller-chosen name.
//
// The OSV wire protocol is spoken by more than OSV.dev — a NOX Intelligence
// endpoint serves it as its baseline surface — so the implementation is shared
// while the identity is not. Without this, a degradation comparing two such
// sources reads "osv.dev withheld a record published by osv.dev", which names
// neither the source at fault nor the one that caught it.
func NewNamed(name, baseURL string, client *http.Client, deg *degrade.Degradations) *Source {
	if name == "" {
		name = "osv.dev"
	}
	return &Source{name: name, baseURL: baseURL, client: client, deg: deg, partial: &partialIndex{}}
}

// Name identifies this source in degradation records and provenance.
func (s *Source) Name() string { return s.name }

// Lookup queries the OSV.dev batch API for vulnerabilities affecting qs. It
// batches requests in groups of batchLimit and returns a map from the caller's
// query index to the vulnerabilities found.
//
// On network errors it returns the results gathered so far rather than failing
// the scan, honouring nox's offline-first design — and records a degradation,
// because a silent empty result is indistinguishable from "no vulnerabilities
// found".
func (s *Source) Lookup(ctx context.Context, qs []vulnsource.Query) (map[int][]vulnsource.Record, error) {
	result := make(map[int][]vulnsource.Record)

	// Only query packages whose ecosystem OSV.dev actually understands. Other
	// "packages" reach the inventory too — notably Docker base images (ecosystem
	// "docker") from Dockerfile scanning — and OSV's /v1/querybatch rejects the
	// WHOLE request with HTTP 400 if any single query carries an unknown
	// ecosystem. That 400 was being swallowed by the graceful-degradation path
	// below, silently dropping every real Go/npm/PyPI result in the batch. So a
	// repo with a Dockerfile got zero dependency-CVE findings. Filter first, and
	// remember each kept query's original index so results map back correctly.
	type indexed struct {
		orig int
		q    vulnsource.Query
	}
	queryable := make([]indexed, 0, len(qs))
	for i, q := range qs {
		if _, ok := Ecosystem(q.Ecosystem); ok {
			queryable = append(queryable, indexed{orig: i, q: q})
		}
	}

	// Build every request body first, so a marshalling error still fails the
	// lookup before anything is sent.
	type batchJob struct {
		items []indexed
		body  []byte
	}
	var jobs []batchJob
	for start := 0; start < len(queryable); start += batchLimit {
		end := min(start+batchLimit, len(queryable))
		batch := queryable[start:end]

		queries := make([]Query, len(batch))
		for i, item := range batch {
			eco, _ := Ecosystem(item.q.Ecosystem)
			queries[i] = Query{
				Package: vulnsource.Package{
					Name:      item.q.Name,
					Ecosystem: eco,
				},
				Version: item.q.Version,
			}
		}

		body, err := json.Marshal(BatchRequest{Queries: queries})
		if err != nil {
			return nil, fmt.Errorf("marshalling OSV request: %w", err)
		}
		jobs = append(jobs, batchJob{items: batch, body: body})
	}

	// The batches are independent, so they are sent together, at most
	// batchConcurrency at a time: a monorepo with thousands of packages waits
	// for one batch's latency rather than one per thousand packages. A batch
	// that fails costs only its own queries -- the others' answers are kept --
	// and is recorded with the number of packages it left unchecked. (Sent one
	// after another, the first failure ended the lookup and lost every later
	// batch as well.)
	url := strings.TrimRight(s.baseURL, "/") + "/v1/querybatch"
	// A request that cannot even be built (a malformed base URL) is a
	// configuration error, not a lookup that failed: it fails the lookup, as it
	// always has, rather than degrading every batch.
	if len(jobs) > 0 {
		if _, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody); err != nil {
			return nil, fmt.Errorf("creating OSV request: %w", err)
		}
	}
	answers := make([][]BatchResult, len(jobs))
	failures := make([]error, len(jobs))
	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	for j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			answers[j], failures[j] = s.queryBatch(ctx, url, jobs[j].body)
		}()
	}
	wg.Wait()

	var partial []partialQuery
	for j, job := range jobs {
		if err := failures[j]; err != nil {
			// Degrade gracefully, but say so: a silent empty result is
			// indistinguishable from "no vulnerabilities found".
			slog.WarnContext(ctx, "OSV query failed; dependency vulnerabilities may be under-reported",
				"error", err, "queries", len(job.items))
			s.deg.Add(degrade.OSV,
				fmt.Sprintf("vulnerability lookup failed for %d packages: %v", len(job.items), err),
				"dependency vulnerabilities are under-reported; this scan cannot confirm the absence of known CVEs")
			continue
		}
		for i, br := range answers[j] {
			if i >= len(job.items) {
				continue
			}
			if len(br.Vulns) > 0 {
				result[job.items[i].orig] = br.Vulns
			}
			if br.Completeness() == Partial {
				partial = append(partial, partialQuery{idx: job.items[i].orig, q: job.items[i].q, why: br.Coverage.partialReason(), mirror: br.Coverage.fromMirror()})
			}
		}
	}
	s.recordPartial(ctx, partial)

	// /v1/querybatch returns only {id, modified}; fetch the detail that
	// severity mapping and import-path scoping depend on. Each result slice is
	// hydrated in place — never reassigned — because map iteration order is
	// randomised and rebuilding the map from a flattened slice would attribute
	// vulnerabilities to the wrong packages.
	ids, validators := needed(s.cache, result)
	details := fetchVulnDetails(ctx, s.client, s.baseURL, s.cache, validators, ids)
	for _, vs := range result {
		applyVulnDetails(vs, details)
	}

	return result, nil
}

type partialQuery struct {
	idx int
	q   vulnsource.Query
	why string
	// mirror is true when live OSV was not consulted for this query.
	mirror bool
}

// maxPartialListed bounds how many packages a degradation names, so a service
// that answers a monorepo partially does not produce a megabyte of detail.
const maxPartialListed = 20

// recordPartial reports the packages the service said it did not fully check.
// The list is sorted, so the degradation is identical on every run.
func (s *Source) recordPartial(ctx context.Context, partial []partialQuery) {
	set := make(map[int]struct{}, len(partial))
	for _, p := range partial {
		set[p.idx] = struct{}{}
	}
	s.partial.mu.Lock()
	s.partial.set = set
	s.partial.mu.Unlock()
	if len(partial) == 0 {
		return
	}
	lines := make([]string, len(partial))
	for i, p := range partial {
		lines[i] = fmt.Sprintf("%s/%s@%s (%s)", p.q.Ecosystem, p.q.Name, p.q.Version, p.why)
	}
	sort.Strings(lines)
	shown := lines
	if len(shown) > maxPartialListed {
		shown = append(append([]string{}, lines[:maxPartialListed]...),
			fmt.Sprintf("and %d more", len(lines)-maxPartialListed))
	}
	slog.WarnContext(ctx, "vulnerability source answered incompletely", "source", s.name, "queries", len(partial))
	impact := "an empty or short advisory list for these packages is not proof they are free of known vulnerabilities"
	for _, p := range partial {
		if p.mirror {
			impact = fmt.Sprintf("answered from %s's mirror because live OSV was unavailable: "+
				"advisories published or changed since the mirror last synced may be missing, "+
				"and %s", s.name, impact)
			break
		}
	}
	s.deg.Add(degrade.IntelIncomplete,
		fmt.Sprintf("%s answered %d package(s) incompletely: %s", s.name, len(partial), strings.Join(shown, "; ")),
		impact)
}

// queryBatch sends one /v1/querybatch request. A transport error, a non-200
// status and an undecodable body are all failures of that batch.
func (s *Source) queryBatch(ctx context.Context, url string, body []byte) ([]BatchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.acceptDegraded {
		req.Header.Set(AcceptDegradedHeader, AcceptDegradedMirror)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeBatchResponse(resp)
}

// HydrateDetails fills in the fields /v1/querybatch does not return.
//
// The batch endpoint answers only "which advisory IDs match this package", as
// {id, modified} pairs — no severity, summary or affected ranges. Everything
// downstream therefore fell back to defaults: every dependency finding was
// reported at SeverityMedium with an empty summary, regardless of its real
// CVSS. Since enforcing gates key on high/critical, a critical dependency CVE
// could never block a build.
//
// Each distinct ID is fetched once from /v1/vulns/{id} and the result is copied
// into every Record sharing it. Hydration is best-effort: on any failure the
// original entry is left untouched, so a lookup problem degrades severity
// accuracy but never loses a finding.
func HydrateDetails(ctx context.Context, client *http.Client, baseURL string, vulns []vulnsource.Record) {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	applyVulnDetails(vulns, fetchVulnDetails(ctx, client, baseURL, nil, nil, ids))
}

// needed returns the advisory ids that must be fetched from upstream: those the
// cache cannot serve at the exact version the batch query just reported.
//
// It also folds the cache hits straight into result, so a fully cached lookup
// issues no detail requests at all.
func needed(cache AdvisoryCache, result map[int][]vulnsource.Record) (ids []string, validators map[string]string) {
	validators = make(map[string]string)
	seen := make(map[string]struct{})
	for _, vs := range result {
		for i := range vs {
			id := vs[i].ID
			if id == "" {
				continue
			}
			if cache != nil {
				if rec, ok := cache.Get(id, vs[i].Modified); ok {
					// The batch answer's annotations describe THIS answer;
					// the cached copy's describe an earlier one.
					rec.Provenance, rec.SameAs, rec.Disagreement = vs[i].Provenance, vs[i].SameAs, vs[i].Disagreement
					vs[i] = rec
					continue
				}
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			validators[id] = vs[i].Modified
			ids = append(ids, id)
		}
	}
	return ids, validators
}

// fetchVulnDetails retrieves advisory detail for each distinct ID, concurrently
// and at most once per ID. IDs that cannot be fetched are simply absent from
// the returned map, which callers treat as "leave the finding as it is".
func fetchVulnDetails(ctx context.Context, client *http.Client, baseURL string, cache AdvisoryCache, validators map[string]string, ids []string) map[string]vulnsource.Record {
	unique := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id != "" {
			unique[id] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return nil
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failures int
	)
	out := make(map[string]vulnsource.Record, len(unique))
	sem := make(chan struct{}, hydrateConcurrency)

	for id := range unique {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			detail, err := fetchVulnDetail(ctx, client, baseURL, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				return
			}
			if cache != nil {
				// Store under the validator the batch reported, which is what
				// the next lookup will ask with — not the detail's own, which
				// carries more precision and would never be matched.
				cache.Put(id, validators[id], detail)
			}
			out[id] = detail
		}(id)
	}
	wg.Wait()

	if failures > 0 {
		slog.WarnContext(ctx, "OSV detail lookup failed for some advisories; severity may be under-reported",
			"failed", failures, "total", len(unique))
	}
	return out
}

// applyVulnDetails copies fetched detail onto the matching entries in vulns,
// in place. Only fields the batch response could not supply are overwritten.
func applyVulnDetails(vulns []vulnsource.Record, details map[string]vulnsource.Record) {
	for i := range vulns {
		detail, ok := details[vulns[i].ID]
		if !ok {
			continue
		}
		if detail.Modified != "" {
			vulns[i].Modified = detail.Modified
		}
		if detail.Withdrawn != "" {
			vulns[i].Withdrawn = detail.Withdrawn
		}
		if detail.Summary != "" {
			vulns[i].Summary = detail.Summary
		}
		if detail.Details != "" {
			vulns[i].Details = detail.Details
		}
		if len(detail.Severity) > 0 {
			vulns[i].Severity = detail.Severity
		}
		if len(detail.Aliases) > 0 {
			vulns[i].Aliases = detail.Aliases
		}
		if len(detail.Affected) > 0 {
			vulns[i].Affected = detail.Affected
		}
		if detail.DatabaseSpecific.Severity != "" {
			vulns[i].DatabaseSpecific = detail.DatabaseSpecific
		}
		// OSV.dev never sends this, but a service speaking the OSV wire
		// protocol does — and the detail endpoint is the only place it can
		// arrive, since querybatch returns nothing but {id, modified}. Dropping
		// it here would silently strip status and corroboration from every
		// record in production while hand-built unit tests kept passing.
		if detail.Intelligence != nil {
			vulns[i].Intelligence = detail.Intelligence
		}
		// Annotations on the batch record describe this answer and win; the
		// detail's are only a fallback for a batch that carried none.
		if len(vulns[i].Provenance) == 0 {
			vulns[i].Provenance = detail.Provenance
		}
		if len(vulns[i].SameAs) == 0 {
			vulns[i].SameAs = detail.SameAs
		}
		if len(vulns[i].Disagreement) == 0 {
			vulns[i].Disagreement = detail.Disagreement
		}
	}
}

// fetchVulnDetail retrieves a single advisory from OSV's /v1/vulns/{id}.
func fetchVulnDetail(ctx context.Context, client *http.Client, baseURL, id string) (vulnsource.Record, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/vulns/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return vulnsource.Record{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return vulnsource.Record{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return vulnsource.Record{}, fmt.Errorf("OSV vuln lookup for %s returned status %d", id, resp.StatusCode)
	}

	var v vulnsource.Record
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return vulnsource.Record{}, err
	}

	// Confirm we got back the record we asked for. Any JSON object decodes into
	// a Record without error, so an intercepting proxy or captive portal
	// answering 200 with unrelated JSON would otherwise yield a well-formed but
	// entirely empty advisory — silently blanking a real finding's severity and
	// fix version, which is exactly the failure hydration exists to prevent.
	if v.ID != id {
		return vulnsource.Record{}, fmt.Errorf("OSV vuln lookup for %s returned mismatched record %q", id, v.ID)
	}
	return v, nil
}

// decodeBatchResponse reads and decodes an OSV batch response. It returns
// an error for non-200 status codes or decode failures.
func decodeBatchResponse(resp *http.Response) ([]BatchResult, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}
	var br BatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, err
	}
	return br.Results, nil
}

// Ecosystem maps a nox internal ecosystem name to the ecosystem string expected
// by the OSV.dev API. The bool is false when OSV has no matching ecosystem
// (e.g. "docker" base images), so callers can skip those packages rather than
// poisoning a batch query — OSV rejects an entire /v1/querybatch request with
// HTTP 400 if any one query names an unknown ecosystem.
func Ecosystem(eco string) (string, bool) {
	switch eco {
	case "go":
		return "Go", true
	case "npm":
		return "npm", true
	case "pypi":
		return "PyPI", true
	case "rubygems":
		return "RubyGems", true
	case "cargo":
		return "crates.io", true
	case "maven":
		return "Maven", true
	case "gradle":
		return "Maven", true
	case "nuget":
		return "NuGet", true
	// The three below were parsed by the CLI for a long time and never
	// queried: an ecosystem missing here is filtered out of the batch
	// silently, so a composer.lock project reported zero advisories with no
	// degradation to say why. The OSV names are the ones its schema lists.
	case "composer", "packagist":
		return "Packagist", true
	case "pub":
		return "Pub", true
	case "hex":
		return "Hex", true
	default:
		return "", false
	}
}

// EcosystemName maps nox's internal ecosystem names to the ecosystem strings
// expected by the OSV.dev API, returning the input unchanged for ecosystems OSV
// does not recognise (used only for best-effort name/version matching in
// already-returned records, not for issuing queries).
func EcosystemName(eco string) string {
	if osv, ok := Ecosystem(eco); ok {
		return osv
	}
	return eco
}

package vulnsource

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nox-hq/nox-core/degrade"
)

// VerifyingSource answers from one source while checking it against another.
//
// Replacing a neutral public database with a richer source trades a known trust
// root for a new one, and introduces a threat the public database does not
// have. Poisoning by addition — an invented vulnerability — is noisy and
// eventually noticed. Denial by omission is silent: a source that withholds a
// real CVE produces a clean scan, and nothing downstream can distinguish "no
// vulnerability" from "not told about the vulnerability".
//
// So the superset claim is checked on every lookup rather than trusted. The
// intelligence source answers; the reference source is asked the same question;
// the difference is classified:
//
//   - the reference has a record the intelligence source did not return —
//     SUPPRESSION. Reported loudly, and the record is still returned, so a
//     failing source degrades trust without ever costing a finding.
//   - the intelligence source has records the reference does not — the added
//     value, carried through with its own status.
//   - the reference could not be reached — the property was not checked, which
//     is reported as such rather than passing for a clean verification.
//
// The zero value is not usable; construct with NewVerifying.
type VerifyingSource struct {
	intel     Source
	reference Source

	// intelDeg collects the intelligence source's own degradations, for the
	// same reason refDeg is separate: a source that reached the network and
	// failed answers with an empty map and a degradation, not an error, and
	// without its own collector that empty answer is indistinguishable from
	// one that withheld every record. An unreachable source is reported as
	// unreachable, and the reference answers in its place.
	intelDeg *degrade.Degradations

	// refDeg collects the reference source's own degradations, kept separate
	// from the scan's collector on purpose. When the reference fails, the
	// intelligence source may have answered perfectly — the honest impact is
	// "the superset property was not verified", not the reference's own "these
	// vulnerabilities are under-reported", which would be false and alarming.
	refDeg *degrade.Degradations

	deg *degrade.Degradations

	mu     sync.Mutex
	result Verification
}

// Discrepancy is one record the two sources disagreed about.
type Discrepancy struct {
	Query  Query
	VulnID string
	Status Status
}

// Verification is the outcome of comparing the two sources.
type Verification struct {
	// Suppressed lists records the reference published and the intelligence
	// source did not return. Any entry means the superset property failed.
	Suppressed []Discrepancy

	// Lagged lists records the reference published after the intelligence
	// source's mirror last synced, which the source therefore could not have
	// returned. They are restored into the answer like suppressed ones but do
	// not fail the superset property: lag is expected behaviour of a mirror,
	// not evidence of withholding, and it needs no degradation.
	Lagged []Discrepancy

	// Added lists records only the intelligence source returned — what the
	// richer source is actually buying.
	Added []Discrepancy

	// Checked reports whether the comparison happened at all. False means the
	// reference could not be reached, and neither list means anything.
	Checked bool
}

// Holds reports whether the superset property held on a comparison that
// actually ran. An unchecked verification does not hold — absence of a detected
// suppression is not evidence of none.
func (v Verification) Holds() bool { return v.Checked && len(v.Suppressed) == 0 }

// SuppressionRate is the share of reference records the intelligence source
// failed to return, in [0,1]. It is the metric a deployment gates on: a build
// that starts dropping advisories fails its own rollout.
//
// An unchecked verification rates 1 — the worst value — because a rollout must
// not be promoted on a check that never ran.
func (v Verification) SuppressionRate() float64 {
	if !v.Checked {
		return 1
	}
	total := len(v.Suppressed) + len(v.Added)
	if total == 0 {
		return 0
	}
	return float64(len(v.Suppressed)) / float64(total)
}

// NewVerifying returns a Source that answers from the intelligence source built
// by newIntel and checks it against the reference built by newReference.
//
// Both sources are built rather than passed so the VerifyingSource owns their
// degradation collectors, which is what lets it tell "the reference disagreed"
// from "the reference never answered" — and "the intelligence source withheld
// a record" from "the intelligence source never answered". deg may be nil.
func NewVerifying(newIntel, newReference func(*degrade.Degradations) Source, deg *degrade.Degradations) *VerifyingSource {
	intelDeg := &degrade.Degradations{}
	refDeg := &degrade.Degradations{}
	return &VerifyingSource{
		intel:     newIntel(intelDeg),
		reference: newReference(refDeg),
		intelDeg:  intelDeg,
		refDeg:    refDeg,
		deg:       deg,
	}
}

// Name identifies the source being verified, not the verifier — the records
// come from the intelligence source, and provenance should say so.
func (v *VerifyingSource) Name() string { return v.intel.Name() }

// Verification returns the outcome of the most recent Lookup.
func (v *VerifyingSource) Verification() Verification {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.result
}

// Lookup queries both sources and returns the intelligence source's records,
// with any record the reference published but the intelligence source withheld
// added back.
//
// Filling the gap is deliberate. The alternative — return what the intelligence
// source said and merely complain — makes a compromised or broken source able
// to hide vulnerabilities from a scan that the operator was told is a superset.
// A discrepancy must cost trust, never coverage.
func (v *VerifyingSource) Lookup(ctx context.Context, qs []Query) (map[int][]Record, error) {
	var (
		intelOut, refOut map[int][]Record
		intelErr, refErr error
		wg               sync.WaitGroup
	)

	wg.Add(2)
	go func() { defer wg.Done(); intelOut, intelErr = v.intel.Lookup(ctx, qs) }()
	go func() { defer wg.Done(); refOut, refErr = v.reference.Lookup(ctx, qs) }()
	wg.Wait()

	// An intelligence source that cannot answer at all is a hard failure: there
	// is nothing to verify and nothing to report.
	if intelErr != nil {
		return nil, intelErr
	}
	if intelOut == nil {
		intelOut = make(map[int][]Record)
	}
	// Reachability is judged on lookup failures only. A failed advisory-detail
	// fetch (degrade.AdvisoryDetail) means a record kept a default severity, not
	// that the source could not be reached or its IDs compared; it is reported
	// separately, and only for the records this scan uses.
	refLookupFailures := lookupFailures(v.refDeg)
	refFailed := refErr != nil || len(refLookupFailures) > 0

	// A partial answer is not a failed one. The source reached us and told us
	// what it did not cover; that is forwarded as its own degradation, and
	// must not be mistaken below for the source being unreachable.
	unreachable := v.forwardIncomplete()

	// Both sources hydrate the same advisory IDs, so a record one side could
	// not hydrate is filled from the other when it can. Only what neither could
	// hydrate is reported, and only for records the scan uses.
	refGaps := v.fillAdvisoryDetail(intelOut, refOut)

	// An intelligence source that reached the network and failed answered
	// nothing, and nothing is not a suppression. The reference answers in its
	// place — the lookup nox ran before intelligence was the default — and
	// whatever the intelligence source did return is kept, so a partial
	// outage costs only what the richer source would have added.
	if len(unreachable) > 0 {
		detail := unreachable[0].Detail
		if refFailed {
			// Nobody answered. This is the one case that is an under-report,
			// and it is said in the reference's own words.
			v.deg.Add(degrade.OSV,
				fmt.Sprintf("%s unreachable (%s) and %s also failed", v.intel.Name(), detail, v.reference.Name()),
				"dependency vulnerabilities are under-reported; this scan cannot confirm the absence of known CVEs")
		} else {
			v.deg.Add(degrade.IntelUnreachable,
				fmt.Sprintf("%s unreachable (%s); answered by %s alone", v.intel.Name(), detail, v.reference.Name()),
				fmt.Sprintf("this scan is exactly the %s lookup nox runs without an intelligence source; "+
					"nothing was withheld, and nothing the %s source would have added is included",
					v.reference.Name(), v.intel.Name()))
		}
		v.setResult(Verification{Checked: false})
		out, added := union(intelOut, refOut)
		v.reportReferenceDetail(added, refGaps)
		return out, nil
	}

	// The reference is the checker, not the answerer. It failing means the
	// check did not happen — which must be said, not assumed away.
	if refFailed {
		detail := "reference source unavailable"
		if refErr != nil {
			detail = fmt.Sprintf("reference source failed: %v", refErr)
		} else if len(refLookupFailures) > 0 {
			detail = fmt.Sprintf("reference source degraded: %s", refLookupFailures[0].Detail)
		}
		v.deg.Add(degrade.IntelUnverified, detail,
			fmt.Sprintf("the %s source answered but was not checked against a reference; "+
				"this scan cannot confirm it withheld nothing", v.intel.Name()))
		v.setResult(Verification{Checked: false})
		return intelOut, nil
	}

	var partial map[int]struct{}
	if pr, ok := v.intel.(PartialReporter); ok {
		partial = pr.PartialQueries()
	}

	var synced map[int]time.Time
	if mr, ok := v.intel.(MirrorSyncReporter); ok {
		synced = mr.MirrorSyncedAt()
	}

	var restored []recordKey
	result := Verification{Checked: true}
	for i, q := range qs {
		have := idSet(intelOut[i])
		_, truncated := partial[i]
		for _, ref := range refOut[i] {
			if _, ok := have[ref.ID]; ok {
				continue
			}
			if truncated {
				// The source said this answer was partial. Restoring what it
				// did not return is right; calling that withholding is not.
				intelOut[i] = append(intelOut[i], ref)
				restored = append(restored, recordKey{i, ref.ID})
				continue
			}
			if postdatesSync(ref, synced[i]) {
				// The mirror answered completely as of its last sync, and
				// this record changed after it. Restore it; it is lag.
				result.Lagged = append(result.Lagged, Discrepancy{
					Query: q, VulnID: ref.ID, Status: StatusPublished,
				})
				intelOut[i] = append(intelOut[i], ref)
				restored = append(restored, recordKey{i, ref.ID})
				continue
			}
			result.Suppressed = append(result.Suppressed, Discrepancy{
				Query: q, VulnID: ref.ID, Status: StatusPublished,
			})
			// Return it anyway: a discrepancy costs trust, not coverage.
			intelOut[i] = append(intelOut[i], ref)
			restored = append(restored, recordKey{i, ref.ID})
		}

		refHave := idSet(refOut[i])
		for _, rec := range intelOut[i] {
			if _, ok := refHave[rec.ID]; ok {
				continue
			}
			result.Added = append(result.Added, Discrepancy{
				Query: q, VulnID: rec.ID, Status: rec.Status(),
			})
		}
	}

	sortDiscrepancies(result.Suppressed)
	sortDiscrepancies(result.Lagged)
	sortDiscrepancies(result.Added)

	if len(result.Suppressed) > 0 {
		v.deg.Add(degrade.IntelSuppression,
			fmt.Sprintf("%s withheld %d record(s) published by %s: %s",
				v.intel.Name(), len(result.Suppressed), v.reference.Name(),
				strings.Join(vulnIDs(result.Suppressed), ", ")),
			"the vulnerability source is not a superset of its reference; "+
				"the withheld records were restored from the reference for this scan, "+
				"but the source cannot be trusted to report completely")
	}

	v.reportReferenceKeys(restored, refGaps)
	v.setResult(result)
	return intelOut, nil
}

// fillAdvisoryDetail fills each side's unhydrated records from the other (see
// fillDetail), reports the intelligence source's records that stayed
// unhydrated — every one of them is used by the scan — and returns the
// reference gaps that remain, for reporting once it is known which reference
// records the scan uses.
func (v *VerifyingSource) fillAdvisoryDetail(intelOut, refOut map[int][]Record) map[recordKey]struct{} {
	intelFailed := detailFailures(v.intel)
	refFailed := detailFailures(v.reference)
	intelGaps := detailGaps(intelOut, intelFailed)
	refGaps := detailGaps(refOut, refFailed)

	intelLeft := fillDetail(intelOut, refOut, intelGaps, refGaps)
	refLeft := fillDetail(refOut, intelOut, refGaps, intelGaps)

	if v.intelNamesFailures() {
		ids := keyIDs(intelLeft)
		ReportAdvisoryDetail(v.deg, v.intel.Name(), len(ids), ids)
	}
	return refLeft
}

// intelNamesFailures reports whether the intelligence source says which IDs it
// failed to hydrate. One that cannot has its AdvisoryDetail degradation
// forwarded unchanged instead: all its records are used, and none can be filled.
func (v *VerifyingSource) intelNamesFailures() bool {
	_, ok := v.intel.(DetailFailureReporter)
	return ok
}

func (v *VerifyingSource) reportReferenceKeys(used []recordKey, gaps map[recordKey]struct{}) {
	var ids []string
	for _, k := range used {
		if _, bad := gaps[k]; bad {
			ids = append(ids, k.id)
		}
	}
	ReportAdvisoryDetail(v.deg, v.reference.Name(), len(ids), ids)
}

// reportReferenceDetail is reportReferenceKeys for records the union added.
func (v *VerifyingSource) reportReferenceDetail(used []usedRecord, gaps map[recordKey]struct{}) {
	keys := make([]recordKey, len(used))
	for i, u := range used {
		keys[i] = recordKey{u.query, u.rec.ID}
	}
	v.reportReferenceKeys(keys, gaps)
}

// detailFailures returns the IDs src failed to hydrate in its latest lookup, or
// nil when it cannot say.
func detailFailures(src Source) map[string]struct{} {
	if r, ok := src.(DetailFailureReporter); ok {
		return r.DetailFailures()
	}
	return nil
}

// lookupFailures returns d's degradations that mean the source failed to
// answer, leaving out advisory-detail failures, which mean it answered with
// records that kept a default severity.
func lookupFailures(d *degrade.Degradations) []degrade.Degradation {
	var out []degrade.Degradation
	for _, item := range d.Items() {
		if item.Kind != degrade.AdvisoryDetail {
			out = append(out, item)
		}
	}
	return out
}

// postdatesSync reports whether the reference record was changed strictly after
// the mirror's last sync, which is the only thing that excuses its absence from
// a complete mirror answer. Everything unprovable fails closed: no sync time, or
// no parseable Modified (Published when Modified is empty), is not lag. A record
// last touched at or before the sync was in the corpus the mirror answered from.
func postdatesSync(ref Record, syncedAt time.Time) bool {
	if syncedAt.IsZero() {
		return false
	}
	stamp := ref.Modified
	if stamp == "" {
		stamp = ref.Published
	}
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return false
	}
	return t.After(syncedAt)
}

// forwardIncomplete copies the intelligence source's IntelIncomplete
// and AdvisoryDetail degradations to the scan and returns the rest, which are
// failures to answer. An intelligence source that names its failed IDs is
// reported per record by fillAdvisoryDetail; one that cannot is forwarded as is.
func (v *VerifyingSource) forwardIncomplete() []degrade.Degradation {
	var rest []degrade.Degradation
	for _, d := range v.intelDeg.Items() {
		if d.Kind == degrade.AdvisoryDetail && v.intelNamesFailures() {
			continue // reported per record by fillAdvisoryDetail
		}
		if d.Kind == degrade.IntelIncomplete || d.Kind == degrade.AdvisoryDetail {
			v.deg.Add(d.Kind, d.Detail, d.Impact)
			continue
		}
		rest = append(rest, d)
	}
	return rest
}

func (v *VerifyingSource) setResult(r Verification) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.result = r
}

// usedRecord is a record and the query whose answer it joined.
type usedRecord struct {
	query int
	rec   Record
}

// union merges the reference's records into the intelligence source's answer
// without classifying the difference — used when the difference means nothing
// because one side never answered. It also returns the records it added.
func union(intelOut, refOut map[int][]Record) (merged map[int][]Record, added []usedRecord) {
	for i, refs := range refOut {
		have := idSet(intelOut[i])
		for _, r := range refs {
			if _, ok := have[r.ID]; !ok {
				intelOut[i] = append(intelOut[i], r)
				added = append(added, usedRecord{i, r})
			}
		}
	}
	return intelOut, added
}

func idSet(recs []Record) map[string]struct{} {
	out := make(map[string]struct{}, len(recs))
	for _, r := range recs {
		out[r.ID] = struct{}{}
	}
	return out
}

func vulnIDs(ds []Discrepancy) []string {
	out := make([]string, 0, len(ds))
	seen := make(map[string]struct{}, len(ds))
	for _, d := range ds {
		if _, ok := seen[d.VulnID]; ok {
			continue
		}
		seen[d.VulnID] = struct{}{}
		out = append(out, d.VulnID)
	}
	return out
}

// sortDiscrepancies imposes a total order so a verification reads the same on
// every run — the same reason scan output is sorted.
func sortDiscrepancies(ds []Discrepancy) {
	sort.Slice(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if a.Query.Ecosystem != b.Query.Ecosystem {
			return a.Query.Ecosystem < b.Query.Ecosystem
		}
		if a.Query.Name != b.Query.Name {
			return a.Query.Name < b.Query.Name
		}
		if a.Query.Version != b.Query.Version {
			return a.Query.Version < b.Query.Version
		}
		return a.VulnID < b.VulnID
	})
}

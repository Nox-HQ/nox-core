package vulnsource

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/degrade"
)

// DetailFailureReporter is an optional interface for a Source that hydrates
// advisories in a second step. It returns the IDs whose hydration failed in the
// most recent Lookup: those records came back without severity or ranges.
//
// A verifier uses it to report only the failures that matter to the scan — a
// reference record that is never restored or unioned is never used, so its
// missing detail cannot affect any gate.
type DetailFailureReporter interface {
	DetailFailures() map[string]struct{}
}

// maxDetailIDsListed bounds how many advisory IDs a degradation names.
const maxDetailIDsListed = 20

// ReportAdvisoryDetail records, on deg, that findings kept a default severity
// because their advisory detail could not be fetched. It does nothing for a
// count of zero. ids are named (sorted, deduplicated, bounded) when given.
func ReportAdvisoryDetail(deg *degrade.Degradations, source string, findings int, ids []string) {
	if findings <= 0 {
		return
	}
	named := uniqueSorted(ids)
	subject := ""
	if len(named) > 0 {
		shown := named
		if len(shown) > maxDetailIDsListed {
			shown = append(append([]string{}, named[:maxDetailIDsListed]...),
				fmt.Sprintf("and %d more", len(named)-maxDetailIDsListed))
		}
		subject = fmt.Sprintf(" (%s: %s)", source, strings.Join(shown, ", "))
	} else {
		subject = fmt.Sprintf(" (%s)", source)
	}
	deg.Add(degrade.AdvisoryDetail,
		fmt.Sprintf("%d findings kept a default severity; a severity gate may not see them%s", findings, subject),
		"advisory detail (severity, summary, affected ranges) could not be fetched for these records, "+
			"so a critical advisory among them can sit below a fail_on threshold; the findings themselves are not lost")
}

func uniqueSorted(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ApplyContent copies the advisory's own content from detail onto r: the fields
// a detail fetch supplies and the batch answer does not. Empty fields in detail
// leave r's untouched. It deliberately carries nothing about how a particular
// source answered (intelligence, provenance, same-as, disagreement, symbols),
// so content can move between sources without changing whose record it is.
func (r *Record) ApplyContent(detail Record) {
	if detail.Modified != "" {
		r.Modified = detail.Modified
	}
	if detail.Published != "" {
		r.Published = detail.Published
	}
	if detail.Withdrawn != "" {
		r.Withdrawn = detail.Withdrawn
	}
	if detail.Summary != "" {
		r.Summary = detail.Summary
	}
	if detail.Details != "" {
		r.Details = detail.Details
	}
	if len(detail.Severity) > 0 {
		r.Severity = detail.Severity
	}
	if len(detail.Aliases) > 0 {
		r.Aliases = detail.Aliases
	}
	if len(detail.Affected) > 0 {
		r.Affected = detail.Affected
	}
	if detail.DatabaseSpecific.Severity != "" {
		r.DatabaseSpecific = detail.DatabaseSpecific
	}
}

// ApplyDetail merges a hydrated detail record fetched for the same source onto
// r: the advisory content (see ApplyContent) plus the source's own annotations.
func (r *Record) ApplyDetail(detail Record) {
	r.ApplyContent(detail)
	// OSV.dev never sends this, but a service speaking the OSV wire
	// protocol does — and the detail endpoint is the only place it can
	// arrive, since querybatch returns nothing but {id, modified}. Dropping
	// it here would silently strip status and corroboration from every
	// record in production while hand-built unit tests kept passing.
	if detail.Intelligence != nil {
		r.Intelligence = detail.Intelligence
	}
	// Annotations on the batch record describe this answer and win; the
	// detail's are only a fallback for a batch that carried none.
	if len(r.Provenance) == 0 {
		r.Provenance = detail.Provenance
	}
	if len(r.SameAs) == 0 {
		r.SameAs = detail.SameAs
	}
	if len(r.Disagreement) == 0 {
		r.Disagreement = detail.Disagreement
	}
	if len(r.Symbols) == 0 {
		r.Symbols = detail.Symbols
	}
}

// recordKey names one record of one query's answer.
type recordKey struct {
	query int
	id    string
}

// detailGaps lists the records of answer whose ID is in failed.
func detailGaps(answer map[int][]Record, failed map[string]struct{}) map[recordKey]struct{} {
	out := make(map[recordKey]struct{})
	if len(failed) == 0 {
		return out
	}
	for i, recs := range answer {
		for _, r := range recs {
			if _, bad := failed[r.ID]; bad {
				out[recordKey{i, r.ID}] = struct{}{}
			}
		}
	}
	return out
}

// fillDetail fills, in place, the records of dst listed in gaps from the same
// advisory in donor, for every record donor hydrated itself (one not in
// donorGaps). Both sources hydrate the same advisory IDs, so one side's failed
// fetch is not the other's. It returns the gaps that remain.
//
// A donor is used only if it is not an older version of the advisory than the
// record it would fill: the failed record still carries the batch answer's
// modified stamp, and detail older than that describes the wrong text. An
// unprovable order (a missing or unparseable stamp) fills, because both sources
// answered for the same ID and a default severity is the worse outcome.
func fillDetail(dst, donor map[int][]Record, gaps, donorGaps map[recordKey]struct{}) map[recordKey]struct{} {
	remaining := make(map[recordKey]struct{}, len(gaps))
	for k := range gaps {
		filled := false
		for j := range dst[k.query] {
			if dst[k.query][j].ID != k.id {
				continue
			}
			for _, d := range donor[k.query] {
				if d.ID != k.id {
					continue
				}
				if _, bad := donorGaps[k]; bad || olderThan(d.Modified, dst[k.query][j].Modified) {
					continue
				}
				dst[k.query][j].ApplyContent(d)
				filled = true
				break
			}
		}
		if !filled {
			remaining[k] = struct{}{}
		}
	}
	return remaining
}

// olderThan reports whether stamp a is provably earlier than stamp b.
func olderThan(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)
	return errA == nil && errB == nil && ta.Before(tb)
}

func keyIDs(m map[recordKey]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k.id)
	}
	sort.Strings(out)
	return out
}

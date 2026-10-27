package vulnsource

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nox-hq/nox-core/degrade"
)

// detailFake is a source whose records came back from a lookup that reached its
// server but failed to hydrate some of them: it records AdvisoryDetail on the
// collector it was built with and names the failed IDs, as osv.Source does.
type detailFake struct {
	*fakeSource
	failed map[string]struct{}
	synced map[int]time.Time
	own    *degrade.Degradations
}

func (d *detailFake) Lookup(ctx context.Context, qs []Query) (map[int][]Record, error) {
	if len(d.failed) > 0 {
		d.own.Add(degrade.AdvisoryDetail, "3 findings kept a default severity", "gate may not see them")
	}
	return d.fakeSource.Lookup(ctx, qs)
}

func (d *detailFake) DetailFailures() map[string]struct{} { return d.failed }

func (d *detailFake) MirrorSyncedAt() map[int]time.Time { return d.synced }

func failedSet(ids ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

// run wires two detail-aware fakes through a VerifyingSource; each gets the
// collector the verifier built for it.
func runDetail(t *testing.T, intel, ref *detailFake) (*VerifyingSource, map[int][]Record, *degrade.Degradations) {
	t.Helper()
	deg := &degrade.Degradations{}
	v := NewVerifying(
		func(c *degrade.Degradations) Source { intel.own = c; return intel },
		func(c *degrade.Degradations) Source { ref.own = c; return ref },
		deg)
	out, err := v.Lookup(context.Background(), queries("lodash"))
	if err != nil {
		t.Fatal(err)
	}
	return v, out, deg
}

func kindCounts(deg *degrade.Degradations) map[degrade.Kind]int {
	m := map[degrade.Kind]int{}
	for _, d := range deg.Items() {
		m[d.Kind]++
	}
	return m
}

func newDetailFake(name string, failed map[string]struct{}, ids ...string) *detailFake {
	recs := make([]Record, len(ids))
	for i, id := range ids {
		recs[i] = rec(id)
	}
	return &detailFake{
		fakeSource: &fakeSource{name: name, recs: map[string][]Record{"lodash": recs}},
		failed:     failed,
	}
}

// The intelligence source answered; a record that kept a default severity does
// not make it unreachable, unverified, or an under-report. Every intel record is
// used, so the failure is reported on the scan, as itself.
func TestVerifying_IntelDetailFailureIsNotUnreachable(t *testing.T) {
	intel := newDetailFake("nox-intel", failedSet("GHSA-a"), "GHSA-a", "GHSA-b")
	ref := newDetailFake("osv.dev", nil, "GHSA-a", "GHSA-b")
	v, out, deg := runDetail(t, intel, ref)

	k := kindCounts(deg)
	if k[degrade.IntelUnreachable] != 0 || k[degrade.OSV] != 0 {
		t.Errorf("a detail failure was reported as the source failing: %v", k)
	}
	if k[degrade.AdvisoryDetail] != 1 {
		t.Errorf("intel detail failure not reported on the scan exactly once: %v", k)
	}
	if !v.Verification().Checked {
		t.Error("verification did not run although both sources answered")
	}
	if len(out[0]) != 2 {
		t.Errorf("records lost: %+v", out[0])
	}
}

// Reference records that were compared but never used reach no gate: nothing to
// report, and the reference is neither unverified nor failed.
func TestVerifying_ReferenceDetailFailureOnUnusedRecordsIsSilent(t *testing.T) {
	intel := newDetailFake("nox-intel", nil, "GHSA-a", "GHSA-b")
	ref := newDetailFake("osv.dev", failedSet("GHSA-a", "GHSA-b"), "GHSA-a", "GHSA-b")
	v, _, deg := runDetail(t, intel, ref)

	if n := deg.Len(); n != 0 {
		t.Errorf("expected no degradation, got %v", deg.Items())
	}
	if !v.Verification().Checked {
		t.Error("a reference detail failure marked the check as not run")
	}
}

// A reference record restored because the source withheld it is what the scan
// answers with, so its missing detail is reported — and it is still reported as
// a suppression, and the reference is still verified.
func TestVerifying_RestoredReferenceRecordWithoutDetailIsReported(t *testing.T) {
	intel := newDetailFake("nox-intel", nil, "GHSA-a")
	ref := newDetailFake("osv.dev", failedSet("GHSA-w", "GHSA-a"), "GHSA-a", "GHSA-w")
	v, out, deg := runDetail(t, intel, ref)

	k := kindCounts(deg)
	if k[degrade.AdvisoryDetail] != 1 {
		t.Fatalf("restored record without detail not reported: %v", deg.Items())
	}
	if k[degrade.IntelSuppression] != 1 || k[degrade.IntelUnverified] != 0 {
		t.Errorf("verification outcome distorted: %v", k)
	}
	for _, d := range deg.Items() {
		if d.Kind == degrade.AdvisoryDetail {
			if !strings.Contains(d.Detail, "1 findings kept a default severity; a severity gate may not see them") ||
				!strings.Contains(d.Detail, "GHSA-w") || strings.Contains(d.Detail, "GHSA-a)") {
				t.Errorf("detail does not name only the used record and its count: %q", d.Detail)
			}
		}
	}
	if len(out[0]) != 2 || !v.Verification().Checked {
		t.Errorf("answer or verification wrong: %+v", out)
	}
}

// A record restored for lag is in the answer just the same.
func TestVerifying_LagRestoredRecordWithoutDetailIsReported(t *testing.T) {
	newer := Record{ID: "GHSA-new", Modified: mirrorT.Add(time.Hour).Format(time.RFC3339)}
	intel := newDetailFake("nox-intel", nil, "GHSA-have")
	intel.synced = map[int]time.Time{0: mirrorT}
	ref := &detailFake{
		fakeSource: &fakeSource{name: "osv.dev", recs: map[string][]Record{"lodash": {rec("GHSA-have"), newer}}},
		failed:     failedSet("GHSA-new", "GHSA-have"),
	}
	v, _, deg := runDetail(t, intel, ref)

	if len(v.Verification().Lagged) != 1 {
		t.Fatalf("setup: record not treated as lag: %+v", v.Verification())
	}
	k := kindCounts(deg)
	if k[degrade.AdvisoryDetail] != 1 || k[degrade.IntelSuppression] != 0 {
		t.Errorf("lag-restored record without detail: %v", deg.Items())
	}
}

// An unreachable intelligence source leaves the reference's records as the
// answer, so their missing detail counts there too.
func TestVerifying_UnionedReferenceRecordWithoutDetailIsReported(t *testing.T) {
	intel := &fakeSource{name: "nox-intel", unreachable: true}
	ref := newDetailFake("osv.dev", failedSet("GHSA-a"), "GHSA-a")
	deg := &degrade.Degradations{}
	v := NewVerifying(
		func(c *degrade.Degradations) Source { intel.deg, intel.degKind = c, degrade.OSV; return intel },
		func(c *degrade.Degradations) Source { ref.own = c; return ref },
		deg)
	if _, err := v.Lookup(context.Background(), queries("lodash")); err != nil {
		t.Fatal(err)
	}
	k := kindCounts(deg)
	if k[degrade.AdvisoryDetail] != 1 || k[degrade.IntelUnreachable] != 1 || k[degrade.OSV] != 0 {
		t.Errorf("unreachable-intel union: %v", deg.Items())
	}
}

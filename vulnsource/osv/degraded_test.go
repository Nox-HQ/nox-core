package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
)

// Recorded shapes from NOX Intelligence v0.20.0 (nox-intelligence#61): an
// upstream outage answered from the mirror (first query), an ecosystem the
// mirror does not cover (second), and a candidate-store outage where the OSV
// answer is complete but NOX's own candidates were not read (third).
const degradedWire = `{"results":[
 {"vulns":[{"id":"GO-2026-0001","modified":"2026-05-01T00:00:00Z","aliases":["GHSA-xxxx-yyyy-zzzz"],
   "nox_provenance":[{"source":"osv.dev","via":"mirror","retrieved_at":"2026-10-25T04:00:00Z","modified":"2026-05-01T00:00:00Z"}],
   "nox_same_as":["GHSA-xxxx-yyyy-zzzz"]},
  {"id":"GHSA-xxxx-yyyy-zzzz","modified":"2026-05-01T00:00:00Z","aliases":["GO-2026-0001"],
   "nox_provenance":[{"source":"osv.dev","via":"mirror","retrieved_at":"2026-10-25T04:00:00Z","modified":"2026-05-01T00:00:00Z"}],
   "nox_same_as":["GO-2026-0001"]}],
  "nox_coverage":{"status":"degraded","reason":"upstream is unreachable; served from the local mirror corpus synced 2h0m0s ago.","missing":["osv_live"],"source":"mirror","mirror_synced_at":"2026-10-25T04:00:00Z"}},
 {"vulns":null,"nox_coverage":{"status":"unavailable","reason":"ecosystem not in the mirror","missing":["osv_live"]}},
 {"vulns":[{"id":"GHSA-live","modified":"2026-06-01T00:00:00Z","nox_provenance":[{"source":"osv.dev","via":"live","retrieved_at":"2026-10-25T06:00:00Z","modified":"2026-06-01T00:00:00Z"}]}],
  "nox_coverage":{"status":"degraded","reason":"candidate store unreadable","missing":["nox_candidates"]}}
]}`

func TestDecode_ProvenanceAndSameAs(t *testing.T) {
	rs := decode(t, degradedWire)
	r := rs[0].Vulns[0]
	if len(r.Provenance) != 1 || r.Provenance[0] != (vulnsource.Provenance{
		Source: "osv.dev", Via: "mirror", RetrievedAt: "2026-10-25T04:00:00Z", Modified: "2026-05-01T00:00:00Z",
	}) {
		t.Errorf("provenance = %+v", r.Provenance)
	}
	if len(r.SameAs) != 1 || r.SameAs[0] != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("same_as = %v", r.SameAs)
	}
}

// Additive: a plain OSV record has none, and encoding one adds no field.
func TestRecord_AnnotationsAbsentWhenAbsent(t *testing.T) {
	for _, r := range decode(t, plainOSVWire)[0].Vulns {
		if r.Provenance != nil || r.SameAs != nil || r.Disagreement != nil {
			t.Errorf("annotations invented: %+v", r)
		}
	}
	b, _ := json.Marshal(vulnsource.Record{ID: "X"})
	for _, f := range []string{"nox_provenance", "nox_same_as", "nox_disagreement"} {
		if strings.Contains(string(b), f) {
			t.Errorf("%s encoded: %s", f, b)
		}
	}
}

func TestDecode_DegradedAndUnavailableArePartial(t *testing.T) {
	rs := decode(t, degradedWire)
	for i, r := range rs {
		if got := r.Completeness(); got != Partial {
			t.Errorf("result %d: Completeness = %v, want Partial", i, got)
		}
	}
	if c := rs[0].Coverage; c.Source != "mirror" || c.MirrorSyncedAt != "2026-10-25T04:00:00Z" || len(c.Missing) != 1 || c.Missing[0] != "osv_live" {
		t.Errorf("coverage = %+v", c)
	}
}

func TestLookup_DegradedReasonsNameWhatWasMissing(t *testing.T) {
	got, deg := lookupWire(t, degradedWire, npmQueries("a", "b", "c"))
	if len(got[0]) != 2 || len(got[2]) != 1 {
		t.Errorf("real advisories from a degraded answer must be returned: %v", got)
	}
	items := deg.Items()
	if len(items) != 1 || items[0].Kind != degrade.IntelIncomplete || !items[0].Blocks() {
		t.Fatalf("degradations = %+v", items)
	}
	for _, want := range []string{
		"npm/a@1.0.0 (degraded: ", MirrorOnlyNote, "mirror synced 2026-10-25T04:00:00Z",
		"npm/b@1.0.0 (unavailable: ecosystem not in the mirror",
		"npm/c@1.0.0 (degraded: candidate store unreadable; NOX candidate store was not consulted",
	} {
		if !strings.Contains(items[0].Detail, want) {
			t.Errorf("detail lacks %q:\n%s", want, items[0].Detail)
		}
	}
	if !strings.Contains(items[0].Impact, "mirror") || !strings.Contains(items[0].Impact, "live OSV was unavailable") {
		t.Errorf("impact = %q", items[0].Impact)
	}
}

// A candidate-store outage alone is not a mirror answer and must not say so.
func TestLookup_CandidateOutageDoesNotClaimMirror(t *testing.T) {
	wire := `{"results":[{"vulns":[],"nox_coverage":{"status":"degraded","missing":["nox_candidates"]}}]}`
	_, deg := lookupWire(t, wire, npmQueries("a"))
	d := deg.Items()[0]
	if strings.Contains(d.Detail, "mirror") || strings.Contains(d.Impact, "mirror") {
		t.Errorf("claimed a mirror answer: %+v", d)
	}
	if !strings.Contains(d.Detail, "NOX candidate store was not consulted") {
		t.Errorf("detail = %q", d.Detail)
	}
}

func TestLookup_UnknownMissingSourceIsNamed(t *testing.T) {
	wire := `{"results":[{"vulns":[],"nox_coverage":{"status":"degraded","missing":["moon_db"]}}]}`
	_, deg := lookupWire(t, wire, npmQueries("a"))
	if d := deg.Items()[0].Detail; !strings.Contains(d, "not consulted: moon_db") {
		t.Errorf("detail = %q", d)
	}
}

// The opt-in header goes to the intelligence source only, and only when asked.
func TestAcceptDegradedHeader_OnlyWhenOptedIn(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Nox-Accept-Degraded"))
		mu.Unlock()
		_, _ = w.Write([]byte(completeWire))
	}))
	defer srv.Close()
	qs := npmQueries("a")
	if _, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(), qs); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNamed("nox-intelligence", srv.URL, srv.Client(), nil).Lookup(context.Background(), qs); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNamed("nox-intelligence", srv.URL, srv.Client(), nil).WithAcceptDegraded().Lookup(context.Background(), qs); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[0] != "" || seen[1] != "" || seen[2] != "mirror" {
		t.Errorf("header per request = %q, want [\"\" \"\" \"mirror\"]", seen)
	}
}

// Hydration must not drop the batch's annotations, with or without a cache.
func TestLookup_AnnotationsSurviveHydrationAndCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			_, _ = w.Write([]byte(`{"id":"` + id + `","modified":"2026-05-01T00:00:00Z","summary":"detail","nox_provenance":[{"source":"osv.dev","via":"live","retrieved_at":"STALE"}]}`))
			return
		}
		_, _ = w.Write([]byte(degradedWire))
	}))
	defer srv.Close()
	cache := NewMemoryCacheForTest()
	src := NewNamed("nox-intelligence", srv.URL, srv.Client(), nil).WithCache(cache)
	for round := 1; round <= 2; round++ {
		got, err := src.Lookup(context.Background(), npmQueries("a", "b", "c"))
		if err != nil {
			t.Fatal(err)
		}
		r := got[0][0]
		if r.Summary != "detail" {
			t.Fatalf("round %d: not hydrated: %+v", round, r)
		}
		if len(r.Provenance) != 1 || r.Provenance[0].Via != "mirror" || r.Provenance[0].RetrievedAt != "2026-10-25T04:00:00Z" {
			t.Errorf("round %d: provenance = %+v, want the batch's", round, r.Provenance)
		}
		if len(r.SameAs) != 1 {
			t.Errorf("round %d: same_as lost: %v", round, r.SameAs)
		}
	}
}

type memCache struct {
	mu sync.Mutex
	m  map[string]vulnsource.Record
}

func NewMemoryCacheForTest() *memCache { return &memCache{m: map[string]vulnsource.Record{}} }

func (c *memCache) Get(id, v string) (vulnsource.Record, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[id+"@"+v]
	return r, ok
}

func (c *memCache) Put(id, v string, r vulnsource.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id+"@"+v] = r
}

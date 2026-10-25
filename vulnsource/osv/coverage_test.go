package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
)

// Recorded shapes. The first is what NOX Intelligence v0.19.1 emits for a
// batch where the second query hit its pagination cap and the third named an
// ecosystem it never asked upstream about (nox-intelligence#56). The second is
// the same service answering in full. The third is what api.osv.dev sends.
const (
	incompleteWire = `{"results":[
	  {"vulns":[{"id":"GHSA-aaaa","modified":"2026-01-01T00:00:00Z"}],"nox_coverage":{"status":"complete"}},
	  {"vulns":[{"id":"GHSA-bbbb","modified":"2026-01-01T00:00:00Z"}],"nox_coverage":{"status":"incomplete","reason":"pagination stopped at 50 pages"}},
	  {"vulns":[],"nox_coverage":{"status":"unsupported","reason":"no upstream vocabulary for ecosystem"}}
	]}`
	completeWire = `{"results":[{"vulns":[],"nox_coverage":{"status":"complete"}}]}`
	plainOSVWire = `{"results":[{"vulns":[{"id":"GHSA-aaaa","modified":"2026-01-01T00:00:00Z"}]},{}]}`
)

func decode(t *testing.T, wire string) []BatchResult {
	t.Helper()
	var br BatchResponse
	if err := json.Unmarshal([]byte(wire), &br); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return br.Results
}

func TestBatchResult_DecodesServiceCoverage(t *testing.T) {
	rs := decode(t, incompleteWire)
	want := []Completeness{Complete, Partial, Partial}
	for i, w := range want {
		if got := rs[i].Completeness(); got != w {
			t.Errorf("result %d: Completeness = %v, want %v", i, got, w)
		}
	}
	if c := rs[1].Coverage; c == nil || c.Status != CoverageIncomplete || c.Reason != "pagination stopped at 50 pages" {
		t.Errorf("incomplete coverage decoded as %+v", c)
	}
	if rs[2].Coverage.Status != CoverageUnsupported {
		t.Errorf("unsupported coverage decoded as %+v", rs[2].Coverage)
	}
}

func TestBatchResult_CompleteIsExplicit(t *testing.T) {
	if got := decode(t, completeWire)[0].Completeness(); got != Complete {
		t.Errorf("Completeness = %v, want Complete", got)
	}
}

// A plain OSV.dev response says nothing about completeness. Reading that as
// Complete would be a claim nobody made; reading it as Partial would turn every
// OSV scan into a degraded one. It is its own state.
func TestBatchResult_PlainOSVIsUnreportedNotComplete(t *testing.T) {
	for i, r := range decode(t, plainOSVWire) {
		if r.Coverage != nil {
			t.Errorf("result %d: plain OSV decoded a coverage %+v", i, r.Coverage)
		}
		if got := r.Completeness(); got != Unreported {
			t.Errorf("result %d: Completeness = %v, want Unreported", i, got)
		}
	}
}

// A status this client has never heard of must not read as clean.
func TestBatchResult_UnknownOrEmptyStatusFailsClosed(t *testing.T) {
	for _, wire := range []string{
		`{"results":[{"vulns":[],"nox_coverage":{"status":"degraded-by-moon"}}]}`,
		`{"results":[{"vulns":[],"nox_coverage":{}}]}`,
	} {
		if got := decode(t, wire)[0].Completeness(); got != Partial {
			t.Errorf("%s: Completeness = %v, want Partial", wire, got)
		}
	}
}

// Encoding a result without coverage must stay byte-identical to before, so a
// test double or server built on these types does not start emitting the field.
func TestBatchResult_NoCoverageEncodesWithoutField(t *testing.T) {
	b, err := json.Marshal(BatchResult{Vulns: []vulnsource.Record{{ID: "X"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "nox_coverage") {
		t.Errorf("encoded %s", b)
	}
}

func lookupWire(t *testing.T, wire string, qs []vulnsource.Query) (map[int][]vulnsource.Record, *degrade.Degradations) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		w.Header().Set("X-Nox-Intel-Incomplete", "2")
		_, _ = w.Write([]byte(wire))
	}))
	t.Cleanup(srv.Close)
	deg := &degrade.Degradations{}
	got, err := NewNamed("nox-intelligence", srv.URL, srv.Client(), deg).Lookup(context.Background(), qs)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return got, deg
}

func npmQueries(names ...string) []vulnsource.Query {
	out := make([]vulnsource.Query, len(names))
	for i, n := range names {
		out[i] = vulnsource.Query{Ecosystem: "npm", Name: n, Version: "1.0.0"}
	}
	return out
}

func TestLookup_PartialAnswerIsADegradationNamingThePackages(t *testing.T) {
	got, deg := lookupWire(t, incompleteWire, npmQueries("a", "b", "c"))
	if len(got[1]) != 1 {
		t.Errorf("the partial answer's real advisories must still be returned: %v", got)
	}
	items := deg.Items()
	if len(items) != 1 || items[0].Kind != degrade.IntelIncomplete {
		t.Fatalf("degradations = %+v, want one intel_incomplete", items)
	}
	if !items[0].Blocks() {
		t.Error("an incomplete answer must block, not advise")
	}
	d := items[0].Detail
	for _, want := range []string{"npm/b@1.0.0", "pagination stopped at 50 pages", "npm/c@1.0.0", "2 package(s)"} {
		if !strings.Contains(d, want) {
			t.Errorf("detail %q lacks %q", d, want)
		}
	}
	if strings.Contains(d, "npm/a@") {
		t.Errorf("a complete package was named as incomplete: %q", d)
	}
}

func TestLookup_CompleteAndPlainOSVRecordNothing(t *testing.T) {
	for name, wire := range map[string]string{"complete": completeWire, "plain": plainOSVWire} {
		_, deg := lookupWire(t, wire, npmQueries("a"))
		if deg.Len() != 0 {
			t.Errorf("%s: unexpected degradations %+v", name, deg.Items())
		}
	}
}

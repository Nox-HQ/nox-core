package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
)

// batchServer answers /v1/querybatch after delay, reporting one advisory for
// every query whose package name is "vuln-<n>"; fail picks batches (by their
// first package's index) to answer 500 instead. /v1/vulns/* is 404 so
// hydration fails open.
func batchServer(t *testing.T, delay time.Duration, fail func(first string) bool, inFlight, peak *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer inFlight.Add(-1)
		time.Sleep(delay)
		var req BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if fail != nil && fail(req.Queries[0].Package.Name) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		results := make([]BatchResult, len(req.Queries))
		for i, q := range req.Queries {
			results[i] = BatchResult{Vulns: []vulnsource.Record{{ID: "OSV-" + q.Package.Name}}}
		}
		encodeJSON(t, w, BatchResponse{Results: results})
	}))
}

func manyQueries(n int) []vulnsource.Query {
	qs := make([]vulnsource.Query, n)
	for i := range qs {
		qs[i] = vulnsource.Query{Name: "pkg-" + itoa(i), Version: "1.0.0", Ecosystem: "npm"}
	}
	return qs
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// Batches are independent, so they are in flight together: a large monorepo's
// lookups cost one batch's latency, not one per thousand packages. Every query
// still gets its answer at its own index.
func TestLookupSendsBatchesConcurrently(t *testing.T) {
	var inFlight, peak atomic.Int32
	srv := batchServer(t, 150*time.Millisecond, nil, &inFlight, &peak)
	defer srv.Close()

	qs := manyQueries(3*batchLimit + 10) // four batches
	start := time.Now()
	got, err := New(srv.URL, srv.Client(), nil).Lookup(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() < 2 {
		t.Errorf("at most %d batch in flight at once; batches are sent one after another", peak.Load())
	}
	if peak.Load() > batchConcurrency {
		t.Errorf("%d batches in flight, more than the limit of %d", peak.Load(), batchConcurrency)
	}
	if d := time.Since(start); d > 4*150*time.Millisecond {
		t.Errorf("four 150 ms batches took %v", d)
	}
	if len(got) != len(qs) {
		t.Fatalf("%d of %d queries answered", len(got), len(qs))
	}
	for i, q := range qs {
		if recs := got[i]; len(recs) != 1 || recs[0].ID != "OSV-"+q.Name {
			t.Fatalf("query %d (%s) got %v", i, q.Name, recs)
		}
	}
}

// A failed batch costs only its own queries: the others' answers are kept,
// and the failure is recorded with the number of packages it left unchecked.
// One after another, the first failure ended the lookup, so every later batch
// was lost too.
func TestAFailedBatchCostsOnlyItsOwnQueries(t *testing.T) {
	var inFlight, peak atomic.Int32
	failSecond := func(first string) bool { return first == "pkg-"+itoa(batchLimit) }
	srv := batchServer(t, 0, failSecond, &inFlight, &peak)
	defer srv.Close()

	deg := &degrade.Degradations{}
	qs := manyQueries(2*batchLimit + 500) // batches of 1000, 1000, 500; the second fails
	got, err := New(srv.URL, srv.Client(), deg).Lookup(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if want := batchLimit + 500; len(got) != want {
		t.Errorf("%d queries answered, want %d (all but the failed batch)", len(got), want)
	}
	if _, ok := got[batchLimit]; ok {
		t.Error("a query from the failed batch has an answer")
	}
	items := deg.Items()
	if len(items) != 1 {
		t.Fatalf("%d degradations, want 1: %+v", len(items), items)
	}
	if !strings.Contains(items[0].Detail, "1000 packages") {
		t.Errorf("degradation does not count the unchecked packages: %q", items[0].Detail)
	}
}

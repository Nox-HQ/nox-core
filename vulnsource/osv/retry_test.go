package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox-core/vulnsource"
)

// fakeClock stands in for time so no test sleeps: sleeping advances the clock.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	slept  []time.Duration
	onWait func()
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if c.onWait != nil {
		c.onWait()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	c.slept = append(c.slept, d)
	return nil
}

func (c *fakeClock) policy(budget time.Duration, backoffs ...time.Duration) retryPolicy {
	return retryPolicy{
		backoffs: backoffs,
		budget:   budget,
		jitter:   func(d time.Duration) time.Duration { return d },
		sleep:    c.sleep,
		now:      c.now,
	}
}

// detailServer answers the batch with one advisory, GO-1, and its detail with
// whatever status(call) says; calls counts detail requests.
func detailServer(t *testing.T, calls *atomic.Int32, status func(call int32) int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GO-1","modified":"2026-01-01T00:00:00Z"}]}]}`))
			return
		}
		n := calls.Add(1)
		if st := status(n); st != http.StatusOK {
			w.WriteHeader(st)
			return
		}
		_, _ = w.Write([]byte(`{"id":"GO-1","summary":"hydrated"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func lookupGO1(t *testing.T, ctx context.Context, srv *httptest.Server, rp retryPolicy) (*Source, map[int][]vulnsource.Record, *degrade.Degradations) {
	t.Helper()
	deg := &degrade.Degradations{}
	s := New(srv.URL, srv.Client(), deg)
	s.retry = rp
	out, err := s.Lookup(ctx, []vulnsource.Query{{Ecosystem: "go", Name: "example.com/m", Version: "1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	return s, out, deg
}

func TestDetailFetch_TransientServerErrorIsRetriedAndHydrates(t *testing.T) {
	var calls atomic.Int32
	srv := detailServer(t, &calls, func(n int32) int {
		if n == 1 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	clock := &fakeClock{t: time.Unix(0, 0)}
	_, out, deg := lookupGO1(t, context.Background(), srv, clock.policy(5*time.Second, 200*time.Millisecond, 600*time.Millisecond))

	if deg.Len() != 0 {
		t.Errorf("a retried-then-successful fetch was reported: %+v", deg.Items())
	}
	if len(out[0]) != 1 || out[0][0].Summary != "hydrated" {
		t.Errorf("record not hydrated after retry: %+v", out)
	}
	if calls.Load() != 2 || len(clock.slept) != 1 || clock.slept[0] != 200*time.Millisecond {
		t.Errorf("calls=%d slept=%v, want 2 calls and one 200ms wait", calls.Load(), clock.slept)
	}
}

func TestDetailFetch_TooManyRequestsIsRetried(t *testing.T) {
	var calls atomic.Int32
	srv := detailServer(t, &calls, func(n int32) int {
		if n == 1 {
			return http.StatusTooManyRequests
		}
		return http.StatusOK
	})
	clock := &fakeClock{t: time.Unix(0, 0)}
	_, _, deg := lookupGO1(t, context.Background(), srv, clock.policy(5*time.Second, 200*time.Millisecond))
	if deg.Len() != 0 || calls.Load() != 2 {
		t.Errorf("429 not retried: calls=%d deg=%+v", calls.Load(), deg.Items())
	}
}

// A 404 is the source's answer, not a hiccup: retrying it only adds latency.
func TestDetailFetch_NotFoundIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := detailServer(t, &calls, func(int32) int { return http.StatusNotFound })
	clock := &fakeClock{t: time.Unix(0, 0)}
	s, _, deg := lookupGO1(t, context.Background(), srv, clock.policy(5*time.Second, 200*time.Millisecond, 600*time.Millisecond))

	if calls.Load() != 1 || len(clock.slept) != 0 {
		t.Errorf("a 404 was retried: calls=%d slept=%v", calls.Load(), clock.slept)
	}
	if _, ok := s.DetailFailures()["GO-1"]; !ok || deg.Len() != 1 {
		t.Errorf("the 404 is still a missing detail and must be reported: %v %+v", s.DetailFailures(), deg.Items())
	}
}

// Cancellation stops the retrying at once, and a cancelled fetch is not a
// source failing: no degradation claims a failure nobody observed.
func TestDetailFetch_CancellationStopsRetryingAndClaimsNothing(t *testing.T) {
	var calls atomic.Int32
	srv := detailServer(t, &calls, func(int32) int { return http.StatusInternalServerError })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := &fakeClock{t: time.Unix(0, 0), onWait: cancel}
	s, _, deg := lookupGO1(t, ctx, srv, clock.policy(5*time.Second, 200*time.Millisecond, 600*time.Millisecond))

	if calls.Load() != 1 {
		t.Errorf("kept requesting after cancellation: %d calls", calls.Load())
	}
	if deg.Len() != 0 || len(s.DetailFailures()) != 0 {
		t.Errorf("cancellation reported as a detail failure: %v %+v", s.DetailFailures(), deg.Items())
	}
}

// A dead upstream must not multiply scan time: retrying stops once the next
// wait would run past the budget.
func TestDetailFetch_RetryTimeIsCapped(t *testing.T) {
	var calls atomic.Int32
	srv := detailServer(t, &calls, func(int32) int { return http.StatusBadGateway })
	clock := &fakeClock{t: time.Unix(0, 0)}
	s, _, deg := lookupGO1(t, context.Background(), srv, clock.policy(500*time.Millisecond, 200*time.Millisecond, 600*time.Millisecond))

	var total time.Duration
	for _, d := range clock.slept {
		total += d
	}
	if total > 500*time.Millisecond || calls.Load() != 2 {
		t.Errorf("budget not honoured: slept %v over %d calls", clock.slept, calls.Load())
	}
	if _, ok := s.DetailFailures()["GO-1"]; !ok || deg.Len() != 1 {
		t.Errorf("an exhausted retry is still a failure: %v %+v", s.DetailFailures(), deg.Items())
	}
}

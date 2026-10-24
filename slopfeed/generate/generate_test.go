package generate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nox-hq/nox-core/slopfeed"
)

// fakeRegistry is an offline Doer. Names in unregistered answer 404; names in
// flaky answer 503 forever; everything else answers 200.
type fakeRegistry struct {
	mu           sync.Mutex
	unregistered map[string]bool
	flaky        map[string]bool
	calls        int
	userAgents   map[string]int
}

func (f *fakeRegistry) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.userAgents == nil {
		f.userAgents = map[string]int{}
	}
	f.userAgents[req.Header.Get("User-Agent")]++
	name := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/pypi/"), "/json")
	name = strings.TrimPrefix(name, "/")
	code := http.StatusOK
	switch {
	case f.flaky[name]:
		code = http.StatusServiceUnavailable
	case f.unregistered[name]:
		code = http.StatusNotFound
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("{}"))}, nil
}

// sleepRecorder replaces real waiting and records every requested pause.
type sleepRecorder struct {
	mu     sync.Mutex
	pauses []time.Duration
}

func (s *sleepRecorder) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.pauses = append(s.pauses, d)
	s.mu.Unlock()
	return ctx.Err()
}

var fixedNow = func() time.Time { return time.Date(2026, 10, 24, 6, 17, 0, 0, time.UTC) }

func offlineChecker(reg *fakeRegistry, rec *sleepRecorder, o CheckerOptions) *Checker {
	o.Client = reg
	o.Sleep = rec.sleep
	o.PyPIBaseURL = "https://pypi.invalid/pypi"
	o.NPMBaseURL = "https://npm.invalid"
	return NewChecker(o)
}

func TestFeed_OfflineRunIsDeterministicAndVerifies(t *testing.T) {
	unreg := map[string]bool{"openai-utils": true, "axios-retry-async": true, "requests-sdk": true}
	run := func() (*slopfeed.Feed, Report, *fakeRegistry, *sleepRecorder) {
		reg := &fakeRegistry{unregistered: unreg}
		rec := &sleepRecorder{}
		f, rep, err := Feed(context.Background(), Options{
			Checker: offlineChecker(reg, rec, CheckerOptions{}),
			Now:     fixedNow,
		})
		if err != nil {
			t.Fatal(err)
		}
		return f, rep, reg, rec
	}
	f, rep, reg, rec := run()
	f2, _, _, _ := run()

	if f.Digest != f2.Digest || f.GeneratedAt != f2.GeneratedAt {
		t.Fatal("two offline runs with one clock produced different feeds")
	}
	if f.Version != "2026.10.24" || f.GeneratedAt != "2026-10-24T06:17:00Z" || f.Source != DefaultSource {
		t.Fatalf("metadata: %q %q %q", f.Version, f.GeneratedAt, f.Source)
	}
	if rep.Selected != 175 || rep.Checked != 175 || rep.Unregistered != 3 || rep.Written != 3 || rep.Registered != 172 {
		t.Fatalf("report: %+v", rep)
	}
	// Every 404 is re-verified: 172 registered + 3 * 2.
	if reg.calls != 178 || rep.Requests != 178 {
		t.Fatalf("requests: registry saw %d, report says %d", reg.calls, rep.Requests)
	}
	if len(reg.userAgents) != 1 || reg.userAgents[DefaultUserAgent] != 178 {
		t.Fatalf("user agents: %v", reg.userAgents)
	}
	// The rate limit: one DefaultInterval pause after every request.
	if len(rec.pauses) != 178 {
		t.Fatalf("expected 178 pauses, got %d", len(rec.pauses))
	}
	for _, p := range rec.pauses {
		if p != DefaultInterval {
			t.Fatalf("pause %v, want %v", p, DefaultInterval)
		}
	}
	for i, e := range f.Entries {
		if e.VerifiedAt != "2026-10-24" || !unreg[e.Name] {
			t.Errorf("entry %d: %+v", i, e)
		}
		if i > 0 && f.Entries[i-1].Risk < e.Risk {
			t.Error("entries not in descending risk")
		}
	}

	// The generated feed signs and round-trips through the format package.
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := f.Sign(priv, "k"); err != nil {
		t.Fatal(err)
	}
	data, err := slopfeed.Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := slopfeed.Parse(data, slopfeed.VerifyOptions{RequireSignature: true, Verifier: slopfeed.Ed25519Verifier(pub)})
	if err != nil {
		t.Fatalf("generated feed must verify: %v", err)
	}
	if _, ok := loaded.Lookup("pypi", "OpenAI_Utils"); !ok {
		t.Error("generated entry not found by lookup")
	}
}

func TestFeed_InconclusiveIsNeverWritten(t *testing.T) {
	reg := &fakeRegistry{
		unregistered: map[string]bool{"openai-utils": true},
		flaky:        map[string]bool{"openai-utils": true, "axios-retry-async": true},
	}
	rec := &sleepRecorder{}
	f, rep, err := Feed(context.Background(), Options{
		Checker: offlineChecker(reg, rec, CheckerOptions{MaxRetries: 2, Backoff: time.Second}),
		Now:     fixedNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Inconclusive != 2 || rep.Written != 0 || len(f.Entries) != 0 {
		t.Fatalf("report %+v, entries %d", rep, len(f.Entries))
	}
	// Backoff doubles per attempt: 1s then 2s for each flaky name.
	var backoffs []time.Duration
	for _, p := range rec.pauses {
		if p != DefaultInterval {
			backoffs = append(backoffs, p)
		}
	}
	want := []time.Duration{time.Second, 2 * time.Second, time.Second, 2 * time.Second}
	if len(backoffs) != len(want) {
		t.Fatalf("backoffs %v", backoffs)
	}
	for i := range want {
		if backoffs[i] != want[i] {
			t.Fatalf("backoffs %v, want %v", backoffs, want)
		}
	}
}

func TestFeed_BudgetStopsTheRunAndSaysSo(t *testing.T) {
	// Every name is unregistered, so each costs two requests. A budget of 5
	// completes two names and interrupts the third mid re-verification.
	reg := &fakeRegistry{unregistered: map[string]bool{}}
	for _, c := range Select(Candidates(), DefaultLimit) {
		reg.unregistered[c.Name] = true
	}
	rec := &sleepRecorder{}
	f, rep, err := Feed(context.Background(), Options{
		Checker: offlineChecker(reg, rec, CheckerOptions{MaxRequests: 5}),
		Now:     fixedNow,
	})
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("expected ErrBudgetExhausted, got %v", err)
	}
	if f == nil || !rep.BudgetExhausted {
		t.Fatalf("a budget stop returns the partial feed and flags it: %v %+v", f, rep)
	}
	if reg.calls != 5 || rep.Requests != 5 {
		t.Fatalf("budget not enforced: %d calls", reg.calls)
	}
	if rep.Checked != 2 || len(f.Entries) != 2 {
		t.Fatalf("the interrupted name must not be written: %+v, %d entries", rep, len(f.Entries))
	}
	if err := f.VerifyDigest(); err != nil {
		t.Fatal(err)
	}
}

func TestFeed_CancelledContextReturnsNoFeed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reg := &fakeRegistry{}
	rec := &sleepRecorder{}
	n := 0
	f, _, err := Feed(ctx, Options{
		Checker: offlineChecker(reg, rec, CheckerOptions{}),
		Now:     fixedNow,
		Progress: func(int, int) {
			if n++; n == 3 {
				cancel()
			}
		},
	})
	if !errors.Is(err, context.Canceled) || f != nil {
		t.Fatalf("got feed=%v err=%v", f, err)
	}
}

func TestFeed_OptionsOverrideDefaults(t *testing.T) {
	reg := &fakeRegistry{unregistered: map[string]bool{"openai-utils": true}}
	f, rep, err := Feed(context.Background(), Options{
		Checker: offlineChecker(reg, &sleepRecorder{}, CheckerOptions{Interval: -1}),
		Now:     fixedNow,
		Limit:   10,
		Version: "v-test",
		Source:  "nox-intelligence/test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Version != "v-test" || f.Source != "nox-intelligence/test" || rep.Selected != 10 {
		t.Fatalf("%q %q %+v", f.Version, f.Source, rep)
	}
	if f.Entries == nil {
		t.Fatal("an empty feed must encode entries as [], not null")
	}
}

func TestChecker_UnsupportedEcosystemIsAnError(t *testing.T) {
	c := offlineChecker(&fakeRegistry{}, &sleepRecorder{}, CheckerOptions{})
	r, err := c.Check(context.Background(), "x", "cargo")
	if err == nil || r.Verdict != Inconclusive {
		t.Fatalf("got %+v, %v", r, err)
	}
	if c.Requests() != 0 {
		t.Fatal("an unsupported ecosystem must not reach the network")
	}
}

func TestChecker_ConcurrentChecksShareTheRateLimit(t *testing.T) {
	reg := &fakeRegistry{}
	rec := &sleepRecorder{}
	c := offlineChecker(reg, rec, CheckerOptions{MaxRequests: 7})
	var wg sync.WaitGroup
	var mu sync.Mutex
	exhausted := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Check(context.Background(), "react", "npm"); errors.Is(err, ErrBudgetExhausted) {
				mu.Lock()
				exhausted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if reg.calls != 7 || exhausted != 3 || len(rec.pauses) != 7 {
		t.Fatalf("calls %d, exhausted %d, pauses %d", reg.calls, exhausted, len(rec.pauses))
	}
}

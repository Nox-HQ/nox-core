package generate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Verdict classifies a name against a registry.
type Verdict string

// Verdicts.
const (
	// Unregistered means the registry answered 404 twice: the name is claimable.
	Unregistered Verdict = "unregistered"
	// Registered means a package owns the name (200, including 404-then-200).
	Registered Verdict = "registered"
	// Inconclusive is anything that could not be resolved confidently. It is
	// never written to a feed.
	Inconclusive Verdict = "inconclusive"
)

// CheckResult is the outcome of checking one name.
type CheckResult struct {
	Name       string
	Ecosystem  string
	Verdict    Verdict
	HTTPStatus int    // last status that decided the verdict; 0 if none
	Note       string // why a result is inconclusive or was reclassified
}

// Defaults for CheckerOptions zero values.
const (
	DefaultUserAgent      = "nox-slopfeed/1.0 (+https://github.com/nox-hq/nox; supply-chain security research)"
	DefaultInterval       = 400 * time.Millisecond
	DefaultRequestTimeout = 20 * time.Second
	DefaultMaxRetries     = 4
	DefaultBackoff        = time.Second
	DefaultPyPIBaseURL    = "https://pypi.org/pypi"
	DefaultNPMBaseURL     = "https://registry.npmjs.org"
)

// ErrBudgetExhausted is returned once a Checker has made MaxRequests requests.
// A name whose check it interrupts is reported Inconclusive, never Unregistered.
var ErrBudgetExhausted = errors.New("registry request budget exhausted")

// Doer sends an HTTP request. *http.Client satisfies it; tests and services
// inject their own transport, proxy or recorder.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// CheckerOptions configures a Checker. Every zero value selects the default the
// generator has always used.
type CheckerOptions struct {
	// Client sends requests. Nil uses an *http.Client with
	// DefaultRequestTimeout.
	Client Doer
	// Interval is the pause after every completed request: the rate limit.
	// Zero uses DefaultInterval; a negative value disables the pause (for use
	// against a local test server only).
	Interval time.Duration
	// MaxRequests caps the HTTP requests (retries and re-verifications
	// included) this Checker will ever make. Zero means no cap.
	MaxRequests int
	// MaxRetries bounds attempts per request on a transport error, 429 or 5xx.
	// Zero uses DefaultMaxRetries.
	MaxRetries int
	// Backoff is the base of the exponential backoff between retries (base,
	// 2*base, 4*base, ...). Zero uses DefaultBackoff.
	Backoff time.Duration
	// PyPIBaseURL and NPMBaseURL locate the registries' metadata APIs. Empty
	// uses the public registries.
	PyPIBaseURL string
	NPMBaseURL  string
	// UserAgent identifies the caller to registries. Empty uses
	// DefaultUserAgent, a contact string operators can reach us through.
	UserAgent string
	// Sleep waits for d or until ctx is done, returning ctx's error in the
	// latter case. Nil uses a timer. Inject it to test without waiting.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Checker queries PyPI and npm, read-only, to classify names. It is a good
// citizen: a descriptive User-Agent, a pause after every request, exponential
// backoff on 429/5xx, and an optional request budget. It RE-VERIFIES every 404
// with a second query before asserting a name is unregistered (registries are
// eventually consistent; one 404 is not proof), and it never marks a
// registered package as claimable.
//
// A Checker is safe for concurrent use; checks are serialized so the rate
// limit holds across goroutines.
type Checker struct {
	mu       sync.Mutex
	opts     CheckerOptions
	requests atomic.Int64
}

// NewChecker returns a Checker with opts' zero values replaced by defaults.
func NewChecker(opts CheckerOptions) *Checker {
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: DefaultRequestTimeout}
	}
	if opts.Interval == 0 {
		opts.Interval = DefaultInterval
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = DefaultMaxRetries
	}
	if opts.Backoff <= 0 {
		opts.Backoff = DefaultBackoff
	}
	if opts.PyPIBaseURL == "" {
		opts.PyPIBaseURL = DefaultPyPIBaseURL
	}
	if opts.NPMBaseURL == "" {
		opts.NPMBaseURL = DefaultNPMBaseURL
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	if opts.Sleep == nil {
		opts.Sleep = sleepCtx
	}
	opts.PyPIBaseURL = strings.TrimRight(opts.PyPIBaseURL, "/")
	opts.NPMBaseURL = strings.TrimRight(opts.NPMBaseURL, "/")
	return &Checker{opts: opts}
}

// Requests returns how many HTTP requests the Checker has made.
func (c *Checker) Requests() int { return int(c.requests.Load()) }

// Check classifies one name. Registry-level trouble (an unexpected status,
// exhausted retries) yields an Inconclusive result and a nil error, so a run
// carries on. The error is non-nil only when the run itself should stop: the
// context ended, the request budget is spent, or the ecosystem is not one the
// Checker knows. The result is Inconclusive in every such case.
func (c *Checker) Check(ctx context.Context, name, ecosystem string) (CheckResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	res := CheckResult{Name: name, Ecosystem: ecosystem, Verdict: Inconclusive}
	u, err := c.urlFor(name, ecosystem)
	if err != nil {
		res.Note = err.Error()
		return res, err
	}

	code, err := c.get(ctx, u)
	if err != nil {
		res.Note = err.Error()
		return res, stopping(err)
	}
	res.HTTPStatus = code

	switch code {
	case http.StatusOK:
		res.Verdict = Registered
	case http.StatusNotFound:
		// RE-VERIFY: a squattable verdict requires two independent 404s.
		code2, err2 := c.get(ctx, u)
		if err2 != nil {
			res.Note = "404 then error on re-query: " + err2.Error()
			return res, stopping(err2)
		}
		switch code2 {
		case http.StatusNotFound:
			res.Verdict = Unregistered
		case http.StatusOK:
			// Eventual consistency: the name exists after all. Never accuse it.
			res.Verdict = Registered
			res.Note = "404 then 200 on re-query (eventual consistency); treated as registered"
		default:
			res.HTTPStatus = code2
			res.Note = fmt.Sprintf("404 then %d on re-query; inconclusive", code2)
		}
	}
	return res, nil
}

// stopping keeps only the errors that should end a run; anything else was a
// registry problem, already recorded in the result's note.
func stopping(err error) error {
	if errors.Is(err, ErrBudgetExhausted) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

// urlFor builds the metadata URL for a name in an ecosystem.
func (c *Checker) urlFor(name, ecosystem string) (string, error) {
	switch ecosystem {
	case "pypi":
		return c.opts.PyPIBaseURL + "/" + url.PathEscape(name) + "/json", nil
	case "npm":
		return c.opts.NPMBaseURL + "/" + url.PathEscape(name), nil
	default:
		return "", fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
}

// get performs one GET with retries, returning the final HTTP status. It
// pauses after every completed request and backs off exponentially on
// transport errors, 429 and 5xx.
func (c *Checker) get(ctx context.Context, u string) (int, error) {
	for attempt := 0; attempt < c.opts.MaxRetries; attempt++ {
		if limit := c.opts.MaxRequests; limit > 0 && c.Requests() >= limit {
			return -1, fmt.Errorf("%w (%d requests)", ErrBudgetExhausted, limit)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if err != nil {
			return -1, err
		}
		req.Header.Set("User-Agent", c.opts.UserAgent)
		c.requests.Add(1)
		resp, err := c.opts.Client.Do(req)
		if err != nil {
			if serr := c.opts.Sleep(ctx, c.opts.Backoff*time.Duration(1<<attempt)); serr != nil {
				return -1, serr
			}
			continue
		}
		code := resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		switch code {
		case http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			if serr := c.opts.Sleep(ctx, c.opts.Backoff*time.Duration(1<<attempt)); serr != nil {
				return -1, serr
			}
			continue
		}
		if c.opts.Interval > 0 {
			// A cancelled pause is noticed by the next request; the status we
			// already have is still the registry's answer.
			_ = c.opts.Sleep(ctx, c.opts.Interval)
		}
		return code, nil
	}
	return -1, fmt.Errorf("exhausted retries for %s", u)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

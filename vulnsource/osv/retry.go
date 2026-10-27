package osv

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/nox-hq/nox-core/vulnsource"
)

// retryableError marks a failure that may not repeat: a transport error, a 5xx
// or a 429. Anything else — a 404 or other 4xx, a body that does not decode, a
// record for the wrong ID — is the source's answer, and asking again only adds
// latency.
type retryableError struct{ err error }

func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }

// retryPolicy paces repeated attempts at one advisory-detail fetch.
type retryPolicy struct {
	// backoffs[i] is the wait before retry i+1; its length is the retry count.
	backoffs []time.Duration
	// budget caps the time from the start of a lookup's detail fetching to the
	// end of its last wait, so a dead upstream cannot multiply scan time.
	budget time.Duration

	jitter func(time.Duration) time.Duration
	sleep  func(context.Context, time.Duration) error
	now    func() time.Time
}

// defaultRetry is two retries after roughly 200ms and 600ms, within 4s.
func defaultRetry() retryPolicy {
	return retryPolicy{
		backoffs: []time.Duration{200 * time.Millisecond, 600 * time.Millisecond},
		budget:   4 * time.Second,
		jitter: func(d time.Duration) time.Duration {
			// Spread by +/-25% so concurrent fetches that failed together
			// do not retry together.
			return d - d/4 + rand.N(d/2+1) //nolint:gosec // jitter, not security
		},
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		now: time.Now,
	}
}

func (p retryPolicy) orDefault() retryPolicy {
	if p.now == nil {
		return defaultRetry()
	}
	return p
}

// fetchVulnDetailRetrying fetches one advisory, retrying a retryable failure
// within the policy's attempts and the lookup's deadline. A cancelled context
// stops it at once and returns the context's error.
func fetchVulnDetailRetrying(ctx context.Context, client *http.Client, baseURL, id string, rp retryPolicy, deadline time.Time) (vulnsource.Record, error) {
	for attempt := 0; ; attempt++ {
		rec, err := fetchVulnDetail(ctx, client, baseURL, id)
		if err == nil {
			return rec, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return vulnsource.Record{}, cerr
		}
		var re retryableError
		if attempt >= len(rp.backoffs) || !errors.As(err, &re) {
			return vulnsource.Record{}, err
		}
		wait := rp.jitter(rp.backoffs[attempt])
		if rp.now().Add(wait).After(deadline) {
			return vulnsource.Record{}, err
		}
		if serr := rp.sleep(ctx, wait); serr != nil {
			return vulnsource.Record{}, serr
		}
	}
}

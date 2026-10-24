// Package generate produces predictive slopsquat feeds: it models the package
// names LLMs hallucinate, checks public registries read-only for which of them
// are unregistered, and assembles the claimable, high-likelihood ones into a
// slopfeed.Feed.
//
// It is the library form of nox's former cmd/slopfeed, so a scheduler (the
// nox-intelligence service) can run it without depending on the scanner. The
// candidate model, the selection quotas and the scoring are unchanged.
//
// Only Checker touches the network, through an injectable Doer, and the run
// reads the clock only through Options.Now. With both injected, a run is fully
// offline and reproducible, which is how the tests exercise it.
//
// The one claim a generated entry makes is "unregistered + high-likelihood =
// squattable". A name is written only after two 404s; a registered package is
// never written, and neither is an inconclusive one.
package generate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nox-hq/nox-core/slopfeed"
)

// DefaultSource is the Feed.Source written when Options.Source is empty.
const DefaultSource = "github.com/nox-hq/nox-core/slopfeed/generate"

// Options configures one generation run.
type Options struct {
	// Checker classifies names. Nil uses NewChecker(CheckerOptions{}): the
	// public registries, DefaultInterval between requests, no request cap.
	Checker *Checker
	// Limit is how many candidates to check (see Select). Zero uses
	// DefaultLimit; a negative value checks every candidate.
	Limit int
	// Version is the feed's version string. Empty uses Now in UTC as
	// "2006.01.02".
	Version string
	// Source is the generator identity recorded in the feed. Empty uses
	// DefaultSource.
	Source string
	// Now is the clock. Nil uses time.Now. It stamps GeneratedAt, the default
	// Version, and every entry's VerifiedAt.
	Now func() time.Time
	// Progress, when set, is called after each candidate is checked.
	Progress func(checked, total int)
}

// Report accounts for a run, so a caller can tell a feed that is small because
// few names are claimable from one that is small because little was checked.
type Report struct {
	Candidates      int  // names the model produced
	Selected        int  // names chosen for checking
	Checked         int  // names whose check completed
	Unregistered    int  // two 404s
	Registered      int  // a package owns the name
	Inconclusive    int  // could not be resolved; never written
	Written         int  // entries in the feed
	Requests        int  // HTTP requests the Checker has made in total
	BudgetExhausted bool // the Checker's MaxRequests stopped the run early
}

// Feed runs the generator: select candidates, check each against its registry,
// score the unregistered ones and assemble a feed whose digest is set. The
// feed is not signed; call Feed.Sign before publishing.
//
// Entries are ordered by descending risk, then ecosystem, then name.
//
// When the context ends, Feed returns a nil feed and the context's error. When
// the Checker's request budget runs out, it stops checking and returns the
// feed built so far together with an error wrapping ErrBudgetExhausted; the
// unchecked names are simply absent, so publishing that feed is the caller's
// decision to make, not this package's.
func Feed(ctx context.Context, opts Options) (*slopfeed.Feed, Report, error) {
	chk := opts.Checker
	if chk == nil {
		chk = NewChecker(CheckerOptions{})
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	limit := opts.Limit
	if limit == 0 {
		limit = DefaultLimit
	}

	cands := Candidates()
	selected := Select(cands, limit)
	rep := Report{Candidates: len(cands), Selected: len(selected)}

	started := now().UTC()
	verifiedAt := started.Format("2006-01-02")

	var entries []slopfeed.Entry
	var stopErr error
	for _, c := range selected {
		if err := ctx.Err(); err != nil {
			rep.Requests = chk.Requests()
			return nil, rep, err
		}
		r, err := chk.Check(ctx, c.Name, c.Ecosystem)
		if errors.Is(err, ErrBudgetExhausted) {
			rep.BudgetExhausted = true
			stopErr = err
			break
		}
		if err != nil {
			rep.Requests = chk.Requests()
			return nil, rep, err
		}
		rep.Checked++
		switch r.Verdict {
		case Unregistered:
			rep.Unregistered++
			if e, ok := Score(c, r, verifiedAt); ok {
				entries = append(entries, e)
			}
		case Registered:
			rep.Registered++
		default:
			rep.Inconclusive++
		}
		if opts.Progress != nil {
			opts.Progress(rep.Checked, len(selected))
		}
	}
	rep.Requests = chk.Requests()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Risk != entries[j].Risk {
			return entries[i].Risk > entries[j].Risk
		}
		if entries[i].Ecosystem != entries[j].Ecosystem {
			return entries[i].Ecosystem < entries[j].Ecosystem
		}
		return entries[i].Name < entries[j].Name
	})
	rep.Written = len(entries)

	f := &slopfeed.Feed{
		SchemaVersion: slopfeed.SchemaVersion,
		Version:       opts.Version,
		GeneratedAt:   started.Format(time.RFC3339),
		Source:        opts.Source,
		Entries:       entries,
	}
	if f.Version == "" {
		f.Version = started.Format("2006.01.02")
	}
	if f.Source == "" {
		f.Source = DefaultSource
	}
	if f.Entries == nil {
		f.Entries = []slopfeed.Entry{}
	}
	if err := f.SetDigest(); err != nil {
		return nil, rep, fmt.Errorf("digesting generated feed: %w", err)
	}
	return f, rep, stopErr
}

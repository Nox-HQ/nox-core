package generate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The hashes below were computed from nox's own cmd/slopfeed (nox commit
// 29a9246, v1.48.2) by a test compiled into that package, printing each
// section in exactly the format these helpers use. They pin "the candidate
// model did not change in the move" without vendoring 1.1 MB of names.
//
// To regenerate after an INTENDED model change, print the same sections from
// the new code and say in the commit why the model changed.
const (
	// Candidates(): 3701 lines, in order (the order is total: prior, ecosystem, name).
	noxCandidatesSHA256 = "b91bf1684f63b31e782bb99e9100d9c336a662ca6b035e490571302515c5add8"
	// Select(Candidates(), 180): 175 lines, sorted bytewise. Ties in prior are
	// left in sort.Slice's order, which is Go-release dependent, so the set and
	// the multiset of priors are pinned, not the tie order.
	noxSelectedSortedSHA256 = "c68c11e915f90bf7622a808a6e5123ad5f0bffe11d1411c7905f23eab03ccdf3"
	// Score of every candidate as Unregistered on 2026-07-25: 2904 lines.
	noxScoredSHA256 = "dca0bc7ba365809bc41e096048cafac4de3f7864a36b049e48251a329fffc1ab"
)

func candidateLine(c Candidate) string {
	return fmt.Sprintf("%s\t%s\t%s\t%.3f\t%s\t%s\n", c.Ecosystem, c.Name, c.Pattern, c.Prior, c.NeighborOf, c.Reason)
}

func sha(lines []string) string {
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestParity_CandidatesMatchNox(t *testing.T) {
	all := Candidates()
	if len(all) != 3701 {
		t.Fatalf("got %d candidates, nox produced 3701", len(all))
	}
	lines := make([]string, len(all))
	for i, c := range all {
		lines[i] = candidateLine(c)
	}
	if got := sha(lines); got != noxCandidatesSHA256 {
		t.Fatalf("candidate model diverged from nox: sha256 %s", got)
	}
}

func TestParity_SelectionMatchesNox(t *testing.T) {
	sel := Select(Candidates(), DefaultLimit)
	if len(sel) != 175 {
		t.Fatalf("selected %d, nox selected 175", len(sel))
	}
	for i := 1; i < len(sel); i++ {
		if sel[i].Prior > sel[i-1].Prior {
			t.Fatalf("selection not in descending prior at %d", i)
		}
	}
	lines := make([]string, len(sel))
	for i, c := range sel {
		lines[i] = candidateLine(c)
	}
	sort.Strings(lines)
	if got := sha(lines); got != noxSelectedSortedSHA256 {
		t.Fatalf("selection diverged from nox: sha256 %s", got)
	}
}

func TestParity_ScoringMatchesNox(t *testing.T) {
	var lines []string
	for _, c := range Candidates() {
		e, ok := Score(c, CheckResult{Verdict: Unregistered}, "2026-07-25")
		if ok {
			lines = append(lines, fmt.Sprintf("%s\t%s\t%.3f\t%s\t%s\n", e.Ecosystem, e.Name, e.Risk, e.Tier, e.Reason))
		}
	}
	if len(lines) != 2904 {
		t.Fatalf("scored %d entries, nox scored 2904", len(lines))
	}
	if got := sha(lines); got != noxScoredSHA256 {
		t.Fatalf("scoring diverged from nox: sha256 %s\nfirst: %s", got, strings.TrimSpace(lines[0]))
	}
}

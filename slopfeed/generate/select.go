package generate

import "sort"

// DefaultLimit is how many candidates a run checks against registries unless
// told otherwise: the generator's long-standing --limit default.
const DefaultLimit = 180

// Select takes the highest-prior slice of each pattern so every research class
// (obvious / typo / composition) gets real registry coverage rather than one
// class dominating the budget. cands must be prior-sorted, as Candidates
// returns them. A limit <= 0 or >= len(cands) returns cands unchanged.
//
// The per-pattern quotas (obvious 40, typo 70, composition 70) are the
// prototype harness's; with DefaultLimit they select 175 names, because only
// 35 obvious names exist.
//
// The result is ordered by descending prior. Ties keep whatever order Go's
// sort.Slice leaves them in, exactly as nox's cmd/slopfeed did; the set is
// deterministic, and so is the order for a given Go release.
func Select(cands []Candidate, limit int) []Candidate {
	if limit <= 0 || limit >= len(cands) {
		return cands
	}
	quota := map[string]int{"obvious": 40, "typo": 70, "composition": 70}
	byPat := map[string][]Candidate{}
	for _, c := range cands {
		byPat[c.Pattern] = append(byPat[c.Pattern], c)
	}
	seen := map[string]struct{}{}
	var out []Candidate
	for _, pat := range []string{"obvious", "typo", "composition"} {
		list := byPat[pat] // already prior-sorted (Candidates sorts globally)
		q := quota[pat]
		for i := 0; i < len(list) && i < q && len(out) < limit; i++ {
			key := list[i].Ecosystem + "\x00" + list[i].Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, list[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prior > out[j].Prior })
	return out
}

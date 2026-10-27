package vulnsource

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/degrade"
)

// DetailFailureReporter is an optional interface for a Source that hydrates
// advisories in a second step. It returns the IDs whose hydration failed in the
// most recent Lookup: those records came back without severity or ranges.
//
// A verifier uses it to report only the failures that matter to the scan — a
// reference record that is never restored or unioned is never used, so its
// missing detail cannot affect any gate.
type DetailFailureReporter interface {
	DetailFailures() map[string]struct{}
}

// maxDetailIDsListed bounds how many advisory IDs a degradation names.
const maxDetailIDsListed = 20

// ReportAdvisoryDetail records, on deg, that findings kept a default severity
// because their advisory detail could not be fetched. It does nothing for a
// count of zero. ids are named (sorted, deduplicated, bounded) when given.
func ReportAdvisoryDetail(deg *degrade.Degradations, source string, findings int, ids []string) {
	if findings <= 0 {
		return
	}
	named := uniqueSorted(ids)
	subject := ""
	if len(named) > 0 {
		shown := named
		if len(shown) > maxDetailIDsListed {
			shown = append(append([]string{}, named[:maxDetailIDsListed]...),
				fmt.Sprintf("and %d more", len(named)-maxDetailIDsListed))
		}
		subject = fmt.Sprintf(" (%s: %s)", source, strings.Join(shown, ", "))
	} else {
		subject = fmt.Sprintf(" (%s)", source)
	}
	deg.Add(degrade.AdvisoryDetail,
		fmt.Sprintf("%d findings kept a default severity; a severity gate may not see them%s", findings, subject),
		"advisory detail (severity, summary, affected ranges) could not be fetched for these records, "+
			"so a critical advisory among them can sit below a fail_on threshold; the findings themselves are not lost")
}

func uniqueSorted(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

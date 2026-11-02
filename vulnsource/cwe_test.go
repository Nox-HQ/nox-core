package vulnsource

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A GitHub advisory's CWE ids survive decoding, re-marshalling (the service's
// mirror stores records that way) and hydration, and "said none" stays
// distinguishable from "did not say".
func TestCWEIDsSurviveTheRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("testdata/GHSA-xxph-c9ww-hj94.json")
	if err != nil {
		t.Fatal(err)
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.DatabaseSpecific.CWEIDs, ","); got != "CWE-400,CWE-502,CWE-770" {
		t.Fatalf("decoded CWE ids %q", got)
	}
	again, _ := json.Marshal(r)
	var back Record
	if err := json.Unmarshal(again, &back); err != nil || len(back.DatabaseSpecific.CWEIDs) != 3 {
		t.Fatalf("lost in a round trip: %+v %v", back.DatabaseSpecific, err)
	}

	for doc, wantNil := range map[string]bool{
		`{"id":"PYSEC-1"}`: true,
		`{"id":"GHSA-1","database_specific":{"cwe_ids":[]}}`: false,
	} {
		var x Record
		_ = json.Unmarshal([]byte(doc), &x)
		out, _ := json.Marshal(x)
		var y Record
		_ = json.Unmarshal(out, &y)
		if (y.DatabaseSpecific.CWEIDs == nil) != wantNil {
			t.Errorf("%s: re-marshalled CWE ids %#v, want nil=%v", doc, y.DatabaseSpecific.CWEIDs, wantNil)
		}
	}

	// Hydration fills CWE ids from the detail and does not erase them when the
	// detail did not say.
	base := Record{ID: "GHSA-1", DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"}}
	base.ApplyContent(Record{DatabaseSpecific: DatabaseSpecific{CWEIDs: []string{"CWE-79"}}})
	if base.DatabaseSpecific.Severity != "HIGH" || len(base.DatabaseSpecific.CWEIDs) != 1 {
		t.Errorf("after hydration: %+v", base.DatabaseSpecific)
	}
	base.ApplyContent(Record{DatabaseSpecific: DatabaseSpecific{Severity: "CRITICAL"}})
	if base.DatabaseSpecific.Severity != "CRITICAL" || len(base.DatabaseSpecific.CWEIDs) != 1 {
		t.Errorf("a detail without CWE ids erased them: %+v", base.DatabaseSpecific)
	}
}

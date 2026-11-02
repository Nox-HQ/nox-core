package vulnsource

import (
	"encoding/json"
	"testing"
)

// nox_priority as NOX Intelligence sends it decodes in full; a plain OSV
// record has none; the batch record's priority wins over the detail's, which
// is only a fallback.
func TestPriorityDecodesAndMerges(t *testing.T) {
	doc := `{"id":"GHSA-1","nox_priority":{"score":1.42,"band":"epss","rule":"epss-first-severity-cwe/v1",
		"why":"EPSS 42.0%","epss":0.42,"epss_percentile":0.98,"severity":"HIGH","cwe":"CWE-94",
		"severity_rate":0.028,"cwe_rate":0.094}}`
	var r Record
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		t.Fatal(err)
	}
	p := r.Priority
	if p == nil || p.Score != 1.42 || p.Band != "epss" || p.Rule != "epss-first-severity-cwe/v1" ||
		p.EPSS == nil || *p.EPSS != 0.42 || p.CWE != "CWE-94" || p.CWERate != 0.094 {
		t.Fatalf("decoded %+v", p)
	}
	var plain Record
	_ = json.Unmarshal([]byte(`{"id":"GHSA-1"}`), &plain)
	if plain.Priority != nil {
		t.Error("a plain OSV record has no priority")
	}
	out, _ := json.Marshal(plain)
	if string(out) != "" && json.Valid(out) {
		var m map[string]any
		_ = json.Unmarshal(out, &m)
		if _, ok := m["nox_priority"]; ok {
			t.Error("an absent priority must not be emitted")
		}
	}

	batch := Record{ID: "GHSA-1", Priority: &Priority{Rule: "batch"}}
	batch.ApplyDetail(Record{Priority: &Priority{Rule: "detail"}})
	if batch.Priority.Rule != "batch" {
		t.Errorf("the batch priority must win, got %q", batch.Priority.Rule)
	}
	bare := Record{ID: "GHSA-1"}
	bare.ApplyDetail(Record{Priority: &Priority{Rule: "detail"}})
	if bare.Priority == nil || bare.Priority.Rule != "detail" {
		t.Error("the detail's priority must fill a batch record that had none")
	}
}

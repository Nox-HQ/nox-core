package vulnsource

import (
	"encoding/json"
	"reflect"
	"testing"
)

const symbolsRecord = `{
  "id": "GO-2026-1",
  "affected": [{
    "package": {"name": "example.com/mod", "ecosystem": "Go"},
    "ecosystem_specific": {"imports": [{"path": "example.com/mod/pgp", "symbols": ["ReadMessage", "Decrypt"]}, {"path": "example.com/mod/other"}]}
  }],
  "nox_symbols": [
    {"advisory_id": "GO-2026-1", "ecosystem": "Go", "package": "example.com/mod", "fixed_version": "1.2.3",
     "method": "patch-diff", "status": "ok",
     "symbols": [{"name": "Server.Serve", "file": "pgp/s.go", "package": "example.com/mod/pgp", "kind": "method", "change": "modified", "confidence": "medium"},
                 {"name": "Elsewhere", "package": "example.com/mod/other", "change": "removed", "confidence": "low", "role": "caller", "via": "X"}],
     "imports": [{"path": "example.com/mod/pgp", "symbols": ["Server.Serve", "ReadMessage"]}],
     "provenance": {"from_version": "1.2.2", "to_version": "1.2.3"}},
    {"ecosystem": "Go", "package": "example.com/mod", "method": "patch-diff", "status": "inconclusive", "reason": "refactor-scale diff",
     "imports": [{"path": "example.com/mod/pgp", "symbols": ["MustNotAppear"]}]}
  ]
}`

func TestRecordDecodesNoxSymbols(t *testing.T) {
	var r Record
	if err := json.Unmarshal([]byte(symbolsRecord), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Symbols) != 2 || r.Symbols[0].Method != SymbolMethodPatchDiff || r.Symbols[0].Provenance.ToVersion != "1.2.3" {
		t.Fatalf("nox_symbols not decoded: %+v", r.Symbols)
	}
	if r.Symbols[0].Symbols[0].Name != "Server.Serve" || r.Symbols[0].Symbols[1].Role != "caller" {
		t.Errorf("symbols not decoded: %+v", r.Symbols[0].Symbols)
	}
	if got := r.Affected[0].EcosystemSpecific.Imports[0].Symbols; !reflect.DeepEqual(got, []string{"ReadMessage", "Decrypt"}) {
		t.Errorf("OSV imports[].symbols not decoded: %v", got)
	}
	// A plain OSV record has none, and encodes without the field.
	var plain Record
	_ = json.Unmarshal([]byte(`{"id":"X"}`), &plain)
	if b, _ := json.Marshal(plain); json.Valid(b) && reflect.DeepEqual(plain.Symbols, []AffectedSymbols(nil)) == false {
		t.Errorf("plain record grew symbols: %s", b)
	}
}

func TestListedSymbols(t *testing.T) {
	var r Record
	if err := json.Unmarshal([]byte(symbolsRecord), &r); err != nil {
		t.Fatal(err)
	}
	got := r.ListedSymbols("example.com/mod", "example.com/mod/pgp")
	want := []string{"Decrypt", "ReadMessage", "Server.Serve"} // publisher list + usable nox_symbols; MustNotAppear is inconclusive
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListedSymbols = %v, want %v", got, want)
	}
	if got := r.ListedSymbols("example.com/mod", "example.com/mod/nothing"); len(got) != 0 {
		t.Errorf("an unlisted path lists nothing, got %v", got)
	}
	if got := r.ListedSymbols("example.com/other-module", "example.com/mod/pgp"); len(got) != 0 {
		t.Errorf("another module's symbols must not leak, got %v", got)
	}
}

package vulnsource

import "sort"

// Symbol-analysis methods and statuses, as NOX Intelligence reports them.
const (
	// SymbolMethodOSVImports: the advisory publisher's own list, copied.
	SymbolMethodOSVImports = "osv-imports"
	// SymbolMethodPatchDiff: functions whose bodies differ between the last
	// vulnerable and the first fixed release.
	SymbolMethodPatchDiff = "patch-diff"

	// SymbolStatusOK: symbols were found and can be relied on at their stated
	// confidence. Any other status carries no symbols and says nothing about
	// safety.
	SymbolStatusOK = "ok"
)

// AffectedSymbols is the symbol intelligence for one affected package of one
// advisory, for one fixed version (nox_symbols).
//
// # How to use it
//
// Precision against OSV's own lists is roughly 0.3 to 0.5 and recall is
// partial, so this may only RAISE relevance: a call path that reaches a listed
// symbol is a reason to rank a finding higher. It must never be used to
// conclude that a vulnerability is unreachable or irrelevant because none of
// the listed symbols is called. An absent, empty or inconclusive entry says
// nothing about safety. A patch-diff shows where a fix landed; it does not
// prove every listed function is vulnerable.
type AffectedSymbols struct {
	AdvisoryID   string `json:"advisory_id,omitempty"`
	Ecosystem    string `json:"ecosystem"`
	Package      string `json:"package"`
	FixedVersion string `json:"fixed_version,omitempty"`
	// Method is SymbolMethodOSVImports or SymbolMethodPatchDiff.
	Method string `json:"method"`
	// Status is "ok", or "inconclusive" with a Reason. Unknown values are kept
	// as sent and are not "ok".
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Symbols are the changed functions. Empty unless Status is "ok".
	Symbols []ChangedSymbol `json:"symbols,omitempty"`
	// Imports is the same information in OSV's Go imports[].symbols shape.
	Imports []ImportSymbols `json:"imports,omitempty"`
	// Provenance lets a reader re-derive a patch-diff result.
	Provenance SymbolProvenance `json:"provenance"`
}

// ChangedSymbol is one function or method.
type ChangedSymbol struct {
	// Name is qualified the way OSV qualifies Go symbols: "Server.ServeConn"
	// for a method, "ListenAndServe" for a function.
	Name string `json:"name"`
	File string `json:"file,omitempty"`
	// Package is the Go import path holding the symbol; empty elsewhere.
	Package string `json:"package,omitempty"`
	Kind    string `json:"kind,omitempty"`
	// Change is "modified" or "removed".
	Change string `json:"change,omitempty"`
	// Confidence is "high", "medium" or "low".
	Confidence string `json:"confidence,omitempty"`
	// Role is empty for a function the fix changed, and "caller" for an exported
	// function found to reach one by name; callers are always low confidence.
	Role string `json:"role,omitempty"`
	Via  string `json:"via,omitempty"`
}

// ImportSymbols mirrors OSV's Go ecosystem_specific.imports[] entry.
type ImportSymbols struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

// SymbolProvenance names what a patch-diff compared.
type SymbolProvenance struct {
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
}

// ListedSymbols returns the sorted, de-duplicated names listed for the import
// path importPath of module pkg, from the publisher's own OSV imports and from
// every usable nox_symbols entry. Only usable entries contribute: an
// inconclusive or non-ok entry lists nothing.
//
// An empty result means "no symbol is listed". It is not a statement that no
// symbol is affected; see AffectedSymbols.
func (r *Record) ListedSymbols(pkg, importPath string) []string {
	set := map[string]struct{}{}
	for _, aff := range r.Affected {
		if aff.Package.Name != pkg {
			continue
		}
		for _, im := range aff.EcosystemSpecific.Imports {
			if im.Path != importPath {
				continue
			}
			for _, s := range im.Symbols {
				set[s] = struct{}{}
			}
		}
	}
	for _, as := range r.Symbols {
		if as.Package != pkg || as.Status != SymbolStatusOK {
			continue
		}
		for _, im := range as.Imports {
			if im.Path != importPath {
				continue
			}
			for _, s := range im.Symbols {
				set[s] = struct{}{}
			}
		}
		for _, cs := range as.Symbols {
			if cs.Package == importPath && cs.Name != "" {
				set[cs.Name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

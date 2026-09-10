package degrade

import "testing"

// The zero value blocks.
//
// A degradation nobody classified is one nobody thought about, and the safe
// reading of "did not check" is that it matters. Every existing producer builds
// Degradation without this field, so the default decides what happens to all of
// them — and the direction that fails closed is the only defensible one for a
// type whose whole purpose is to stop "did not look" reading as "found
// nothing".
func TestAnUnclassifiedDegradationBlocks(t *testing.T) {
	var d Degradation
	if !d.Blocks() {
		t.Error("the zero Degradation does not block. A producer that did not think " +
			"about this gets the permissive answer, which is how a gate quietly stops " +
			"gating.")
	}
}

// Add keeps the blocking default, so no existing call site changes meaning.
func TestAddIsBlockingByDefault(t *testing.T) {
	var d Degradations
	d.Add(Plugin, "required plugin failed to install", "its findings are absent, not clean")
	items := d.Items()
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if !items[0].Blocks() {
		t.Error("Add produced an advisory degradation; every existing call site would " +
			"silently stop gating")
	}
}

// AddAdvisory is the deliberate act.
//
// The case it exists for: nox reports installed plugins that are NOT in
// plugins.required. That is capability the operator declined, and a CI gate
// counting entries failed builds on it — the inverse of the condition the gate
// exists for. See klarlabs-studio/.github#80.
func TestAddAdvisoryDoesNotBlock(t *testing.T) {
	var d Degradations
	d.AddAdvisory(Plugin, "15 installed plugin(s) are not in plugins.required",
		"their findings are absent from this scan; add the ones you want")
	items := d.Items()
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if items[0].Blocks() {
		t.Error("AddAdvisory produced a blocking degradation")
	}
	if !items[0].Advisory {
		t.Error("the field was not set, so a consumer reading it directly sees blocking")
	}
}

// An advisory alongside a blocking one does not mask it. This is the shape a
// real scan produces, and the one a naive filter gets wrong.
func TestAdvisoryAndBlockingCoexist(t *testing.T) {
	var d Degradations
	d.AddAdvisory(Plugin, "undeclared plugins", "add the ones you want")
	d.Add(OSV, "OSV unreachable", "cannot confirm the absence of known CVEs")

	var blocking, advisory int
	for _, item := range d.Items() {
		if item.Blocks() {
			blocking++
			continue
		}
		advisory++
	}
	if blocking != 1 {
		t.Errorf("blocking = %d, want 1", blocking)
	}
	if advisory != 1 {
		t.Errorf("advisory = %d, want 1", advisory)
	}
}

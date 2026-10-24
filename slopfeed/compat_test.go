package slopfeed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures in testdata were produced by nox's own implementation
// (core/analyzers/slop/feed at nox commit 29a9246, v1.48.2), not by this
// package. Each test below therefore asks one question: does the moved code
// read and write exactly the bytes the code it replaces did?
//
//   - nox-bundled-2026.07.25.json: nox's bundled feed, copied byte for byte.
//   - nox-signed-golden.json: the same entries signed by nox's Feed.Sign with
//     a fixed, public test seed (0x01..0x20) and key id "golden-test-key".
//   - canonical-sample.input.json / canonical-sample.golden: entries chosen to
//     exercise the encoding's edges (HTML escaping, U+2028, non-ASCII, float
//     formatting, omitempty, sort order), and nox's CanonicalEntries of them.

const (
	// bundledFileSHA256 pins the fixture itself, so a re-copied or re-formatted
	// file cannot silently replace the one nox ships.
	bundledFileSHA256 = "db9426947750c9ae6b907f2316ef71f19a6fcd894f886be72dd98910eea1d8fc"
	bundledDigest     = "sha256:f9ae0d9a50569e6ab8a6ed2e138a69f13fdcb8f51160eccfb3b73620ab9871e1"
	bundledEntries    = 62

	goldenSignature = "JPu88uBYnEPCzRYb2e2gNA/7BGuYkVCNLCraTbEejQH6fnbC6wBkQ4iPk7Mw2lx+4bteE0LCc1UFW7mruAwKBg=="
	goldenKeyID     = "golden-test-key"

	sampleDigest = "sha256:224b7066bff102aebded891023df9ce730ba8c37a314d0e503215fbff9c3b2bf"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// goldenKey is the fixed test key the signed fixture was made with. It is
// public by construction and signs nothing but test fixtures.
func goldenKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestCompat_NoxBundledFeedVerifies(t *testing.T) {
	data := readFixture(t, "nox-bundled-2026.07.25.json")
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != bundledFileSHA256 {
		t.Fatalf("fixture is not nox's bundled feed: sha256 %s", got)
	}

	loaded, err := Parse(data, VerifyOptions{})
	if err != nil {
		t.Fatalf("nox's bundled feed must verify unchanged: %v", err)
	}
	if loaded.Digest() != bundledDigest || loaded.Len() != bundledEntries {
		t.Fatalf("got digest %s with %d entries", loaded.Digest(), loaded.Len())
	}
	if loaded.Version() != "2026.07.25" {
		t.Fatalf("version %q", loaded.Version())
	}
	// Recompute rather than trust the declared value Parse compared against.
	got, err := ComputeDigest(loaded.Feed.Entries)
	if err != nil || got != bundledDigest {
		t.Fatalf("recomputed digest %s, %v", got, err)
	}
	for _, e := range loaded.Feed.Entries {
		if e.Name == "" || (e.Ecosystem != EcosystemPyPI && e.Ecosystem != EcosystemNPM) {
			t.Errorf("bundled entry malformed: %+v", e)
		}
		if e.Tier != TierCritical && e.Tier != TierHigh && e.Tier != TierMedium {
			t.Errorf("bundled entry has unexpected tier: %+v", e)
		}
	}
	if _, ok := loaded.Lookup(EcosystemPyPI, "OpenAI_Utils"); !ok {
		t.Error("normalized lookup of a bundled PyPI entry missed")
	}
}

func TestCompat_NoxSignedFeedVerifies(t *testing.T) {
	data := readFixture(t, "nox-signed-golden.json")
	pub := goldenKey().Public().(ed25519.PublicKey)

	opts := VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)}
	loaded, err := Parse(data, opts)
	if err != nil {
		t.Fatalf("a feed signed by nox must verify under the moved code: %v", err)
	}
	if loaded.Digest() != bundledDigest {
		t.Fatalf("signing changed the digest: %s", loaded.Digest())
	}

	// The PEM nox embedded in the signature must be accepted as a pinned key.
	v, err := PEMEd25519Verifier([]byte(loaded.Feed.Signature.PublicKeyPEM))
	if err != nil {
		t.Fatalf("nox-written public key PEM rejected: %v", err)
	}
	if _, err := Parse(data, VerifyOptions{RequireSignature: true, Verifier: v}); err != nil {
		t.Fatalf("verify via nox-written PEM: %v", err)
	}

	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Parse(data, VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(other)}); err == nil {
		t.Fatal("nox-signed feed verified under an unrelated key")
	}
}

// TestCompat_SignReproducesNoxBytes signs the unsigned bundled feed with the
// golden key and requires the result to equal, byte for byte, the file nox's
// implementation wrote: same digest, same signature, same PEM, same encoding.
// Ed25519 is deterministic, so any difference is a difference in the code.
func TestCompat_SignReproducesNoxBytes(t *testing.T) {
	var f Feed
	if err := json.Unmarshal(readFixture(t, "nox-bundled-2026.07.25.json"), &f); err != nil {
		t.Fatal(err)
	}
	if err := f.Sign(goldenKey(), goldenKeyID); err != nil {
		t.Fatal(err)
	}
	if f.Signature.Value != goldenSignature {
		t.Fatalf("signature differs from nox's:\n got %s\nwant %s", f.Signature.Value, goldenSignature)
	}
	got, err := Encode(&f)
	if err != nil {
		t.Fatal(err)
	}
	if want := readFixture(t, "nox-signed-golden.json"); !bytes.Equal(got, want) {
		t.Fatalf("encoded signed feed differs from nox's output (%d vs %d bytes)", len(got), len(want))
	}
}

func TestCompat_CanonicalEncodingGolden(t *testing.T) {
	var entries []Entry
	if err := json.Unmarshal(readFixture(t, "canonical-sample.input.json"), &entries); err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	if want := readFixture(t, "canonical-sample.golden"); !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes differ from nox's:\n got %s\nwant %s", got, want)
	}
	if d, _ := ComputeDigest(entries); d != sampleDigest {
		t.Fatalf("digest %s, want %s", d, sampleDigest)
	}

	// Input order must not matter.
	reversed := make([]Entry, len(entries))
	for i, e := range entries {
		reversed[len(entries)-1-i] = e
	}
	again, _ := CanonicalEntries(reversed)
	if !bytes.Equal(again, got) {
		t.Fatal("canonical bytes depend on input order")
	}
}

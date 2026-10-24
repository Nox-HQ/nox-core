// Package slopfeed defines the predictive slopsquat blocklist: a signed,
// versioned, content-addressed list of package names that an LLM is likely to
// hallucinate and that were verified UNREGISTERED (squattable) when the feed
// was generated.
//
// It is shared because two parties must agree on it byte for byte. The
// generator (nox-intelligence, on a schedule) writes and signs feeds; the
// scanner (nox) verifies and consumes them. A second definition of the
// canonical bytes on either side would make every signature fail, or worse,
// let a re-weighted copy verify on one side only.
//
// The package is pure: no I/O, no network, no clock, no randomness. It encodes,
// digests, signs and verifies bytes handed to it. Reading a feed from disk,
// fetching one over HTTPS and caching it are the caller's concern, and so is
// generating one (see package generate, which holds the network checker).
//
// # Trust model
//
//   - Every feed carries a content digest, "sha256:<hex>", over a canonical
//     serialization of its entries (CanonicalEntries). Parse recomputes it and
//     rejects any feed whose bytes do not match. Verification fails closed: a
//     feed that does not verify is never returned, and malformed input never
//     panics.
//   - A feed may carry an Ed25519 signature over the same canonical bytes. A
//     verifier checks it against a key the operator pinned out of band, never
//     against the key a feed describes itself with.
//
// # Compatibility
//
// This code was extracted from nox's core/analyzers/slop/feed. The canonical
// bytes, the digest and the signature scheme are unchanged, and that is pinned
// by tests against the feed nox bundles and against a feed signed by nox's own
// implementation — not merely promised.
package slopfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// SchemaVersion is the feed schema identifier this package understands. It is a
// namespaced, versioned string so a future breaking change gets a new value and
// an old consumer refuses a feed it cannot interpret rather than misreading it.
const SchemaVersion = "slopsquat-blocklist/v1"

// Ecosystem values used in a feed. They match nox's canonical internal
// ecosystem names, so a consumer can look up an imported package without
// translation.
const (
	EcosystemPyPI = "pypi"
	EcosystemNPM  = "npm"
)

// Tier buckets a squattable name by risk. Only these three tiers are ever
// written to a feed: a name that scores below medium is not likely enough to
// assert as a predictive target.
const (
	TierCritical = "critical"
	TierHigh     = "high"
	TierMedium   = "medium"
)

// Pattern names the hallucination mode a candidate name was derived from.
const (
	PatternObvious     = "obvious"
	PatternTypo        = "typo"
	PatternComposition = "composition"
)

// Entry is a single high-risk, currently-unregistered package name.
//
// The only claim an Entry makes is the narrow, defensible one: this name was
// UNREGISTERED (verified on VerifiedAt) and matches a high-likelihood
// hallucination pattern, so an attacker could register it to catch
// hallucinated installs. It never accuses an existing package.
//
// The field order is part of the canonical encoding. Reordering, renaming or
// adding a field changes every digest and invalidates every signature.
type Entry struct {
	Name       string  `json:"name"`
	Ecosystem  string  `json:"ecosystem"`             // "pypi" | "npm"
	Pattern    string  `json:"pattern"`               // obvious | composition | typo
	NeighborOf string  `json:"neighbor_of,omitempty"` // real stem it derives from
	Risk       float64 `json:"risk"`                  // [0,1] LLM-emission-derived risk
	Tier       string  `json:"tier"`                  // critical | high | medium
	Reason     string  `json:"reason"`                // human-readable rationale
	VerifiedAt string  `json:"verified_at"`           // date the 404 was confirmed
}

// Signature carries an Ed25519 signature over the feed's canonical entry bytes.
// Value is base64 (standard encoding). PublicKeyPEM is recorded for
// transparency and diagnosis only; no verifier in this package trusts it.
type Signature struct {
	Algorithm    string `json:"algorithm"` // "ed25519"
	KeyID        string `json:"key_id,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Value        string `json:"value"`
}

// Feed is the artifact: metadata plus the entry list, bound together by a
// content digest. Only Entries are covered by the digest and the signature;
// the metadata fields are descriptive.
type Feed struct {
	SchemaVersion string     `json:"schema_version"`
	Version       string     `json:"version"`      // human feed version, e.g. "2026.07.25"
	GeneratedAt   string     `json:"generated_at"` // RFC3339 timestamp
	Source        string     `json:"source"`       // generator identity
	Digest        string     `json:"digest"`       // "sha256:<hex>" over CanonicalEntries
	Signature     *Signature `json:"signature,omitempty"`
	Entries       []Entry    `json:"entries"`
}

// CanonicalEntries returns the deterministic byte serialization of entries that
// the digest and the signature are computed over. Entries are sorted by
// (ecosystem, name) so the bytes do not depend on input order; fields are
// emitted in struct order. It is the sole definition of "the content".
//
// It returns an error only for an entry JSON cannot represent: a NaN or
// infinite Risk. Such a feed could never be parsed back, so it must not be
// digested or signed either.
func CanonicalEntries(entries []Entry) ([]byte, error) {
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Ecosystem != sorted[j].Ecosystem {
			return sorted[i].Ecosystem < sorted[j].Ecosystem
		}
		return sorted[i].Name < sorted[j].Name
	})
	for _, e := range sorted {
		if math.IsNaN(e.Risk) || math.IsInf(e.Risk, 0) {
			return nil, fmt.Errorf("entry %s/%s has a non-finite risk", e.Ecosystem, e.Name)
		}
	}
	data, err := json.Marshal(sorted)
	if err != nil {
		return nil, fmt.Errorf("encoding canonical entries: %w", err)
	}
	return data, nil
}

// ComputeDigest returns the "sha256:<hex>" digest over the canonical entries.
func ComputeDigest(entries []Entry) (string, error) {
	content, err := CanonicalEntries(entries)
	if err != nil {
		return "", err
	}
	return digestOf(content), nil
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SetDigest computes and stores the digest for the feed's current entries.
func (f *Feed) SetDigest() error {
	d, err := ComputeDigest(f.Entries)
	if err != nil {
		return err
	}
	f.Digest = d
	return nil
}

// VerifyDigest recomputes the digest over the entries and compares it with the
// declared one. A missing, malformed or mismatched digest is an error.
func (f *Feed) VerifyDigest() error {
	if f.Digest == "" {
		return errors.New("feed carries no digest")
	}
	alg, hexVal, ok := strings.Cut(f.Digest, ":")
	if !ok || alg != "sha256" {
		return fmt.Errorf("unsupported or malformed digest %q", f.Digest)
	}
	if len(hexVal) != sha256.Size*2 {
		return fmt.Errorf("digest hex has wrong length: %d", len(hexVal))
	}
	if _, err := hex.DecodeString(hexVal); err != nil {
		return fmt.Errorf("digest hex invalid: %w", err)
	}
	got, err := ComputeDigest(f.Entries)
	if err != nil {
		return err
	}
	if got != f.Digest {
		return fmt.Errorf("feed digest mismatch: computed %s, declared %s", got, f.Digest)
	}
	return nil
}

// VerifyOptions controls how strictly a feed is verified.
type VerifyOptions struct {
	// RequireSignature rejects a feed that has no signature, and requires the
	// signature to verify under Verifier. When false, a signature is verified
	// only if present and Verifier is set; its absence is tolerated.
	RequireSignature bool
	// Verifier checks the signature. When nil, signature checking is skipped.
	// Digest integrity is enforced regardless.
	Verifier SignatureVerifier
}

// Verify checks the feed's schema, digest and, per opts, its signature. It is
// what Parse applies after decoding, exposed so a producer can check a feed it
// has just signed before publishing it.
//
// A present-but-invalid signature is an error even when RequireSignature is
// false: a bad signature is a stronger red flag than no signature at all.
func (f *Feed) Verify(opts VerifyOptions) error {
	if f.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported feed schema %q (want %q)", f.SchemaVersion, SchemaVersion)
	}
	if err := f.VerifyDigest(); err != nil {
		return err
	}
	if !opts.RequireSignature && (f.Signature == nil || opts.Verifier == nil) {
		return nil
	}
	if f.Signature == nil {
		return errors.New("feed requires a signature but carries none")
	}
	if opts.Verifier == nil {
		return errors.New("feed requires a signature but no verifier is configured")
	}
	content, err := CanonicalEntries(f.Entries)
	if err != nil {
		return err
	}
	if err := opts.Verifier(content, f.Signature); err != nil {
		return fmt.Errorf("feed signature verification failed: %w", err)
	}
	return nil
}

// Encode serializes a feed the way the generator has always written it:
// two-space indented JSON with a trailing newline. The file bytes are not what
// the digest covers, but one encoder keeps every producer's output diffable.
func Encode(f *Feed) ([]byte, error) {
	if f == nil {
		return nil, errors.New("nil feed")
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding feed: %w", err)
	}
	return append(data, '\n'), nil
}

// Loaded is a verified feed indexed for O(1) lookups.
type Loaded struct {
	Feed  *Feed
	index map[string]map[string]Entry // ecosystem -> normalized name -> entry
}

// Parse decodes, verifies and indexes a feed from raw JSON. It fails closed:
// any decode error, schema mismatch, digest mismatch or failed signature check
// returns a nil *Loaded and an error, and malformed input never panics.
func Parse(data []byte, opts VerifyOptions) (*Loaded, error) {
	if len(data) == 0 {
		return nil, errors.New("empty feed")
	}
	var f Feed
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("decoding feed: %w", err)
	}
	if err := f.Verify(opts); err != nil {
		return nil, err
	}
	idx := make(map[string]map[string]Entry, 2)
	for _, e := range f.Entries {
		if idx[e.Ecosystem] == nil {
			idx[e.Ecosystem] = make(map[string]Entry)
		}
		idx[e.Ecosystem][NormalizeName(e.Ecosystem, e.Name)] = e
	}
	return &Loaded{Feed: &f, index: idx}, nil
}

// Lookup reports whether name (in ecosystem) is a feed entry. Names are
// normalized, so "OpenAI_Utils" and "openai-utils" match on PyPI.
func (l *Loaded) Lookup(ecosystem, name string) (Entry, bool) {
	if l == nil {
		return Entry{}, false
	}
	m := l.index[ecosystem]
	if m == nil {
		return Entry{}, false
	}
	e, ok := m[NormalizeName(ecosystem, name)]
	return e, ok
}

// Len returns the number of entries in the feed.
func (l *Loaded) Len() int {
	if l == nil || l.Feed == nil {
		return 0
	}
	return len(l.Feed.Entries)
}

// Version returns the feed's version string.
func (l *Loaded) Version() string {
	if l == nil || l.Feed == nil {
		return ""
	}
	return l.Feed.Version
}

// Digest returns the feed's content digest.
func (l *Loaded) Digest() string {
	if l == nil || l.Feed == nil {
		return ""
	}
	return l.Feed.Digest
}

// NormalizeName canonicalizes a package name for cross-referencing. PyPI names
// follow PEP 503 (lowercase; runs of "._-" collapse to a single "-"); npm and
// other names are matched as written, trimmed.
func NormalizeName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	if ecosystem != EcosystemPyPI {
		return name
	}
	name = strings.ToLower(name)
	name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return name
}

package slopfeed

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// AlgorithmEd25519 is the only signature algorithm a feed uses.
const AlgorithmEd25519 = "ed25519"

// PEM block types this package reads and writes.
const (
	pemTypeRawPublic  = "ED25519 PUBLIC KEY"
	pemTypeRawPrivate = "ED25519 PRIVATE KEY"
	pemTypePKCS8      = "PRIVATE KEY"
)

// Sign recomputes the feed's digest and attaches an Ed25519 signature over the
// canonical entry bytes — the bytes the digest covers. Because the digest is
// recomputed first, an entry changed after SetDigest cannot slip past unsigned.
//
// keyID is a free-form label naming the signing key (rotation, audit). The
// signer's public key is recorded in Signature.PublicKeyPEM for transparency
// only; verifiers check against a key pinned out of band.
//
// Ed25519 signing is deterministic, so the same entries and key always yield
// the same signature.
func (f *Feed) Sign(priv ed25519.PrivateKey, keyID string) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("ed25519 private key has wrong size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	content, err := CanonicalEntries(f.Entries)
	if err != nil {
		return err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("deriving public key from private key")
	}
	f.Digest = digestOf(content)
	f.Signature = &Signature{
		Algorithm:    AlgorithmEd25519,
		KeyID:        keyID,
		PublicKeyPEM: EncodePublicKeyPEM(pub),
		Value:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, content)),
	}
	return nil
}

// SignatureVerifier verifies a signature over a feed's canonical content. It
// returns nil when the signature is valid. Making it a function lets a consumer
// pin a key, defer to another trust system, or accept a build-time key without
// this package embedding any trust root.
type SignatureVerifier func(content []byte, sig *Signature) error

// Ed25519Verifier returns a SignatureVerifier that checks an Ed25519 signature
// against pub, ignoring any key embedded in the feed: a self-described key is
// not a trust root.
func Ed25519Verifier(pub ed25519.PublicKey) SignatureVerifier {
	return func(content []byte, sig *Signature) error {
		if sig == nil {
			return errors.New("no signature present")
		}
		if sig.Algorithm != AlgorithmEd25519 {
			return fmt.Errorf("unsupported signature algorithm %q", sig.Algorithm)
		}
		raw, err := base64.StdEncoding.DecodeString(sig.Value)
		if err != nil {
			return fmt.Errorf("decoding signature: %w", err)
		}
		if len(raw) != ed25519.SignatureSize {
			return fmt.Errorf("signature has wrong length: %d", len(raw))
		}
		if !ed25519.Verify(pub, content, raw) {
			return errors.New("signature does not verify under the configured key")
		}
		return nil
	}
}

// PEMEd25519Verifier builds an Ed25519Verifier from a PEM-encoded public key
// whose body is the raw 32-byte key, the form EncodePublicKeyPEM writes.
func PEMEd25519Verifier(pemData []byte) (SignatureVerifier, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block in public key")
	}
	if len(block.Bytes) == ed25519.PublicKeySize {
		return Ed25519Verifier(ed25519.PublicKey(block.Bytes)), nil
	}
	return nil, fmt.Errorf("unexpected public key length: %d", len(block.Bytes))
}

// EncodePublicKeyPEM encodes a raw Ed25519 public key as a PEM block of type
// "ED25519 PUBLIC KEY" with the raw 32-byte key as its body. PEMEd25519Verifier
// accepts it, so a key written here can be pinned directly.
func EncodePublicKeyPEM(pub ed25519.PublicKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: pemTypeRawPublic, Bytes: pub}))
}

// ParsePrivateKeyPEM decodes an Ed25519 signing key from PEM. It accepts the
// two forms a maintainer or a secret store is likely to hold:
//
//   - PKCS#8 ("PRIVATE KEY"), what `openssl genpkey -algorithm ed25519` writes;
//   - raw ("ED25519 PRIVATE KEY"), whose body is the 64-byte private key or the
//     32-byte seed.
//
// Anything else is an error rather than a guess.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in signing key")
	}
	switch block.Type {
	case pemTypePKCS8:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 signing key: %w", err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key is not Ed25519 (got %T)", key)
		}
		return priv, nil
	case pemTypeRawPrivate:
		switch len(block.Bytes) {
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(block.Bytes), nil
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(block.Bytes), nil
		default:
			return nil, fmt.Errorf("raw Ed25519 key has unexpected length %d", len(block.Bytes))
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q for a signing key", block.Type)
	}
}

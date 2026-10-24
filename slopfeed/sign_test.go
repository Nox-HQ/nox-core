package slopfeed

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	"testing"
)

func pkcs8PEM(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestSignWithParsedKeys signs with each accepted key encoding and checks the
// result verifies under the matching key, the emitted PEM, and nothing else.
func TestSignWithParsedKeys(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	for name, keyPEM := range map[string][]byte{
		"pkcs8":    pkcs8PEM(t, priv),
		"raw-full": pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv}),
		"raw-seed": pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv.Seed()}),
	} {
		t.Run(name, func(t *testing.T) {
			key, err := ParsePrivateKeyPEM(keyPEM)
			if err != nil {
				t.Fatalf("ParsePrivateKeyPEM: %v", err)
			}
			f := &Feed{SchemaVersion: SchemaVersion, Version: "test", Source: "test", Entries: sampleEntries()}
			if err := f.Sign(key, "kid"); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(f)

			if _, err := Parse(raw, VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)}); err != nil {
				t.Fatalf("signed feed must verify: %v", err)
			}
			otherPub, _, _ := ed25519.GenerateKey(nil)
			if _, err := Parse(raw, VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(otherPub)}); err == nil {
				t.Fatal("signature verified under a different key")
			}
			v, err := PEMEd25519Verifier([]byte(EncodePublicKeyPEM(pub)))
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Verify(VerifyOptions{RequireSignature: true, Verifier: v}); err != nil {
				t.Fatalf("emitted public key must verify the feed: %v", err)
			}
		})
	}
}

func TestParsePrivateKeyPEMRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"not pem":      []byte("not a pem"),
		"wrong type":   pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"bad length":   pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: make([]byte, 7)}),
		"bad pkcs8":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"empty":        nil,
		"public block": []byte(EncodePublicKeyPEM(make([]byte, ed25519.PublicKeySize))),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePrivateKeyPEM(data); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestSignResignsAfterMutation: Sign recomputes the digest, so an entry changed
// after SetDigest is covered by the new signature rather than slipping past it.
func TestSignResignsAfterMutation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &Feed{SchemaVersion: SchemaVersion, Entries: sampleEntries()}
	if err := f.SetDigest(); err != nil {
		t.Fatal(err)
	}
	f.Entries[0].Name = "changed-after-digest"
	if err := f.Sign(priv, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(pub)}); err != nil {
		t.Fatalf("re-signed feed must verify: %v", err)
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	f := &Feed{SchemaVersion: SchemaVersion, Entries: sampleEntries()}
	if err := f.Sign(ed25519.PrivateKey{1, 2, 3}, ""); err == nil {
		t.Fatal("short private key accepted")
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	f.Entries[0].Risk = math.NaN()
	if err := f.Sign(priv, ""); err == nil {
		t.Fatal("NaN risk signed")
	}
	if err := f.SetDigest(); err == nil {
		t.Fatal("NaN risk digested")
	}
}

func TestVerifyRejectsPresentButInvalidSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	f := &Feed{SchemaVersion: SchemaVersion, Entries: sampleEntries()}
	if err := f.Sign(priv, ""); err != nil {
		t.Fatal(err)
	}
	// Not required, but present and wrong: still a failure.
	if err := f.Verify(VerifyOptions{Verifier: Ed25519Verifier(otherPub)}); err == nil {
		t.Fatal("present-but-invalid signature tolerated")
	}
	// Not required and no verifier: digest only.
	if err := f.Verify(VerifyOptions{}); err != nil {
		t.Fatalf("digest-only verify: %v", err)
	}
	// Required without a verifier fails closed.
	if err := f.Verify(VerifyOptions{RequireSignature: true}); err == nil {
		t.Fatal("RequireSignature without a verifier passed")
	}
	f.Signature.Algorithm = "rsa"
	if err := f.Verify(VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(priv.Public().(ed25519.PublicKey))}); err == nil {
		t.Fatal("unsupported algorithm accepted")
	}
}

func TestEncodeNil(t *testing.T) {
	if _, err := Encode(nil); err == nil {
		t.Fatal("Encode(nil) must error")
	}
}

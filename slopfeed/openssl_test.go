package slopfeed

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestOpenSSLKeypairSignsAndVerifies follows nox's docs/slopsquat-feed.md
// literally. The fixtures were made with
//
//	openssl genpkey -algorithm ed25519 -out openssl-test.key
//	openssl pkey -in openssl-test.key -pubout -out openssl-test.pub.pem
//
// and are test-only. The private key signs, and the public key an operator is
// told to pin must verify what it signed.
func TestOpenSSLKeypairSignsAndVerifies(t *testing.T) {
	priv, err := ParsePrivateKeyPEM(readFixture(t, "openssl-test.key"))
	if err != nil {
		t.Fatalf("openssl private key: %v", err)
	}
	f := &Feed{SchemaVersion: SchemaVersion, Entries: sampleEntries()}
	if err := f.Sign(priv, "openssl"); err != nil {
		t.Fatal(err)
	}
	v, err := PEMEd25519Verifier(readFixture(t, "openssl-test.pub.pem"))
	if err != nil {
		t.Fatalf("the documented openssl public key cannot be pinned: %v", err)
	}
	if err := f.Verify(VerifyOptions{RequireSignature: true, Verifier: v}); err != nil {
		t.Fatalf("verify under the openssl public key: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if err := f.Verify(VerifyOptions{RequireSignature: true, Verifier: Ed25519Verifier(other)}); err == nil {
		t.Fatal("verified under an unrelated key")
	}
}

func TestPEMEd25519VerifierRejectsNonEd25519PKIX(t *testing.T) {
	// A PKIX block that is not Ed25519 must be refused, not misread.
	bogus := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: make([]byte, 44)})
	if _, err := PEMEd25519Verifier(bogus); err == nil {
		t.Fatal("garbage PKIX accepted")
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PEMEd25519Verifier(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err != nil {
		t.Fatalf("Go-marshalled PKIX Ed25519 key rejected: %v", err)
	}
	if _, err := PEMEd25519Verifier([]byte("no pem here")); err == nil {
		t.Fatal("non-PEM accepted")
	}
}

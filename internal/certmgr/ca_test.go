package certmgr

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestLoadOrCreateAndLeaf(t *testing.T) {
	m, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	chain, key, err := m.Leaf("example.com")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if key == nil || len(chain) != 2 {
		t.Fatalf("unexpected leaf material: key=%v chain=%d", key != nil, len(chain))
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := leaf.VerifyHostname("example.com"); err != nil {
		t.Fatalf("VerifyHostname: %v", err)
	}

	rootPEM, err := os.ReadFile(m.CertPath())
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		t.Fatal("root is not PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "example.com"}); err != nil {
		t.Fatalf("verify leaf chain: %v", err)
	}
}

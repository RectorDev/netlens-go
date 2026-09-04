package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Manager struct {
	dir     string
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	cacheMu sync.RWMutex
	cache   map[string]*tlsCertificate
}

// tlsCertificate is kept private to avoid exposing cache internals.
type tlsCertificate struct {
	certPEM []byte
	keyPEM  []byte
	certDER [][]byte
	key     *ecdsa.PrivateKey
}

func DefaultDataDir() (string, error) {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "NetLens"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".netlens"), nil
}

func LoadOrCreate(dataDir string) (*Manager, error) {
	dir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{dir: dir, cache: make(map[string]*tlsCertificate)}
	crtPath := filepath.Join(dir, "netlens-ca.pem")
	keyPath := filepath.Join(dir, "netlens-ca-key.pem")
	if _, err := os.Stat(crtPath); errors.Is(err, os.ErrNotExist) {
		if err := m.generateRoot(crtPath, keyPath); err != nil {
			return nil, err
		}
	}
	if err := m.loadRoot(crtPath, keyPath); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) CertPath() string    { return filepath.Join(m.dir, "netlens-ca.pem") }
func (m *Manager) CertDERPath() string { return filepath.Join(m.dir, "netlens-ca.cer") }

func (m *Manager) generateRoot(crtPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "NetLens Local Root CA", Organization: []string{"NetLens Local"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.dir, "netlens-ca.cer"), der, 0o600); err != nil {
		return err
	}
	return nil
}

func (m *Manager) loadRoot(crtPath, keyPath string) error {
	cb, err := os.ReadFile(crtPath)
	if err != nil {
		return err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	cp, _ := pem.Decode(cb)
	if cp == nil {
		return errors.New("invalid CA certificate PEM")
	}
	kp, _ := pem.Decode(kb)
	if kp == nil {
		return errors.New("invalid CA key PEM")
	}
	cert, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return err
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(kp.Bytes)
	if err != nil {
		return err
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("CA key is not ECDSA")
	}
	m.cert, m.key = cert, key
	return nil
}

func (m *Manager) Leaf(host string) (certDER [][]byte, key *ecdsa.PrivateKey, err error) {
	hostOnly := host
	if h, _, e := net.SplitHostPort(host); e == nil {
		hostOnly = h
	}
	m.cacheMu.RLock()
	c := m.cache[hostOnly]
	m.cacheMu.RUnlock()
	if c != nil {
		return c.certDER, c.key, nil
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostOnly, Organization: []string{"NetLens Local"}},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.AddDate(0, 0, 30),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(hostOnly); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{hostOnly}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, m.cert, &leafKey.PublicKey, m.key)
	if err != nil {
		return nil, nil, err
	}
	entry := &tlsCertificate{certDER: [][]byte{der, m.cert.Raw}, key: leafKey}
	m.cacheMu.Lock()
	m.cache[hostOnly] = entry
	m.cacheMu.Unlock()
	return entry.certDER, entry.key, nil
}

func (m *Manager) RootSummary() string {
	if m.cert == nil {
		return "unloaded"
	}
	return fmt.Sprintf("%s (expires %s)", m.cert.Subject.CommonName, m.cert.NotAfter.Format("2006-01-02"))
}

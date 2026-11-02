package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

// Signer mints short-lived leaf certificates for intercepted hosts, signed by
// the local CA, and caches them per host. It is used by the transparent
// listener (Phase 7); the HTTP proxy path uses goproxy's own signer, which is
// configured from the same CA.
type Signer struct {
	ca  *CA
	mu  sync.Mutex
	key *ecdsa.PrivateKey
	m   map[string]*tls.Certificate
}

// NewSigner returns a Signer backed by the given CA.
func NewSigner(ca *CA) (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{ca: ca, key: key, m: map[string]*tls.Certificate{}}, nil
}

// GetCertificate satisfies tls.Config.GetCertificate: it returns a leaf
// certificate for the requested server name (SNI), minting and caching one as
// needed.
func (s *Signer) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		name = "localhost"
	}
	return s.For(name)
}

// For returns a cached or freshly minted leaf certificate for host.
func (s *Signer) For(host string) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.m[host]; ok {
		return c, nil
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.Cert, &s.key.PublicKey, s.ca.TLS.PrivateKey)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, s.ca.Cert.Raw},
		PrivateKey:  s.key,
	}
	s.m[host] = leaf
	return leaf, nil
}

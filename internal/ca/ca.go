// Package ca manages Adnesia's local root certificate authority.
//
// On first run we generate a root CA key pair and self-signed certificate,
// store them under the data directory, and install the certificate into the
// system trust store. The proxy then mints a short-lived leaf certificate for
// each intercepted host, signed by this CA, so the browser trusts them.
//
// The private key never leaves this machine. This is the crucial difference
// from a third-party blocker: the only party that can decrypt the traffic is
// code running locally that the user controls.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	certFile = "ca.crt"
	keyFile  = "ca.key"

	commonName = "Adnesia Local Root CA"
	org        = "Adnesia"
)

// CA holds the loaded certificate authority ready for signing leaf certs.
type CA struct {
	TLS  tls.Certificate   // cert + private key, with Leaf populated
	Cert *x509.Certificate // parsed CA certificate
	dir  string
}

// CertPath returns the path to the PEM-encoded CA certificate on disk.
func (c *CA) CertPath() string { return filepath.Join(c.dir, certFile) }

// EnsureCA loads the CA from dir, generating and persisting a new one if none
// exists yet.
func EnsureCA(dir string) (*CA, error) {
	certPEM, certErr := os.ReadFile(filepath.Join(dir, certFile))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, keyFile))

	if certErr == nil && keyErr == nil {
		return loadCA(dir, certPEM, keyPEM)
	}
	if (certErr != nil && !os.IsNotExist(certErr)) || (keyErr != nil && !os.IsNotExist(keyErr)) {
		return nil, fmt.Errorf("reading CA files: %v / %v", certErr, keyErr)
	}
	return generateCA(dir)
}

func loadCA(dir string, certPEM, keyPEM []byte) (*CA, error) {
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	keyPair.Leaf = leaf
	return &CA{TLS: keyPair, Cert: leaf, dir: dir}, nil
}

func generateCA(dir string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Write the key first with restrictive permissions, then the cert.
	if err := os.WriteFile(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("writing CA key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("writing CA cert: %w", err)
	}

	return loadCA(dir, certPEM, keyPEM)
}

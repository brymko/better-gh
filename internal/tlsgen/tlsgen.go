package tlsgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Certs struct {
	CACertPath     string
	ServerCertPath string
	ServerKeyPath  string
}

func EnsureCerts(dir string) (*Certs, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	caCertPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	serverCertPath := filepath.Join(dir, "server.pem")
	serverKeyPath := filepath.Join(dir, "server-key.pem")

	if fileExists(caCertPath) && fileExists(caKeyPath) &&
		fileExists(serverCertPath) && fileExists(serverKeyPath) {
		return &Certs{
			CACertPath:     caCertPath,
			ServerCertPath: serverCertPath,
			ServerKeyPath:  serverKeyPath,
		}, nil
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bgh-proxy CA", Organization: []string{"bgh-proxy"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA cert: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating server key: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA cert: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating server cert: %w", err)
	}

	if err := writePEM(caCertPath, "CERTIFICATE", caCertDER); err != nil {
		return nil, err
	}
	caKeyDER, _ := x509.MarshalECPrivateKey(caKey)
	if err := writePEM(caKeyPath, "EC PRIVATE KEY", caKeyDER); err != nil {
		return nil, err
	}
	if err := writePEM(serverCertPath, "CERTIFICATE", serverCertDER); err != nil {
		return nil, err
	}
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverKey)
	if err := writePEM(serverKeyPath, "EC PRIVATE KEY", serverKeyDER); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, `bgh-proxy: TLS certificates generated in %s
To trust the CA on macOS:

  security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain %s

Or set SSL_CERT_FILE=%s when running gh.

`, dir, caCertPath, caCertPath)

	return &Certs{
		CACertPath:     caCertPath,
		ServerCertPath: serverCertPath,
		ServerKeyPath:  serverKeyPath,
	}, nil
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

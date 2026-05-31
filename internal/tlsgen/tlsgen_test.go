package tlsgen

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCertsGenerates(t *testing.T) {
	dir := t.TempDir()

	certs, err := EnsureCerts(dir)
	if err != nil {
		t.Fatalf("EnsureCerts: %v", err)
	}

	if certs.CACertPath != filepath.Join(dir, "ca.pem") {
		t.Errorf("CACertPath = %q", certs.CACertPath)
	}
	if certs.ServerCertPath != filepath.Join(dir, "server.pem") {
		t.Errorf("ServerCertPath = %q", certs.ServerCertPath)
	}
	if certs.ServerKeyPath != filepath.Join(dir, "server-key.pem") {
		t.Errorf("ServerKeyPath = %q", certs.ServerKeyPath)
	}

	for _, path := range []string{
		filepath.Join(dir, "ca.pem"),
		filepath.Join(dir, "ca-key.pem"),
		filepath.Join(dir, "server.pem"),
		filepath.Join(dir, "server-key.pem"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing file: %s", path)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s: permissions = %o, want 0600", path, info.Mode().Perm())
		}
	}
}

func TestEnsureCertsValid(t *testing.T) {
	dir := t.TempDir()

	certs, err := EnsureCerts(dir)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := tls.LoadX509KeyPair(certs.ServerCertPath, certs.ServerKeyPath)
	if err != nil {
		t.Fatalf("loading server keypair: %v", err)
	}

	serverCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if serverCert.Subject.CommonName != "localhost" {
		t.Errorf("server CN = %q, want localhost", serverCert.Subject.CommonName)
	}

	caCertPEM, _ := os.ReadFile(certs.CACertPath)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("failed to parse CA cert")
	}

	_, err = serverCert.Verify(x509.VerifyOptions{
		Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("server cert not signed by CA: %v", err)
	}
}

func TestEnsureCertsReusesExisting(t *testing.T) {
	dir := t.TempDir()

	certs1, err := EnsureCerts(dir)
	if err != nil {
		t.Fatal(err)
	}

	serverPEM1, _ := os.ReadFile(certs1.ServerCertPath)

	certs2, err := EnsureCerts(dir)
	if err != nil {
		t.Fatal(err)
	}

	serverPEM2, _ := os.ReadFile(certs2.ServerCertPath)

	if string(serverPEM1) != string(serverPEM2) {
		t.Fatal("second EnsureCerts should reuse existing certs")
	}
}

func TestEnsureCertsRegeneratesIfPartiallyMissing(t *testing.T) {
	dir := t.TempDir()

	certs1, err := EnsureCerts(dir)
	if err != nil {
		t.Fatal(err)
	}

	serverPEM1, _ := os.ReadFile(certs1.ServerCertPath)

	os.Remove(filepath.Join(dir, "server-key.pem"))

	certs2, err := EnsureCerts(dir)
	if err != nil {
		t.Fatal(err)
	}

	serverPEM2, _ := os.ReadFile(certs2.ServerCertPath)
	if string(serverPEM1) == string(serverPEM2) {
		t.Fatal("should regenerate when a cert file is missing")
	}
}

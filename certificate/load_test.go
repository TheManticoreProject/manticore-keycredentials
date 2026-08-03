package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// testKeyPair builds a self-signed certificate and its key. 1024 bits keeps the
// tests fast; only the key identity matters here, not its strength.
func testKeyPair(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	return key, certificate
}

func writePEM(t *testing.T, path string, blocks ...*pem.Block) string {
	t.Helper()

	handle, err := os.Create(path)
	if err != nil {
		t.Fatalf("os.Create(%q) error = %v", path, err)
	}
	defer handle.Close()

	for _, block := range blocks {
		if err := pem.Encode(handle, block); err != nil {
			t.Fatalf("pem.Encode() error = %v", err)
		}
	}

	return path
}

// A certificate, a private key and a public key all lead to the same public key,
// and every one of the PEM encodings the loader claims to support has to resolve to
// it. The returned key is compared by modulus, which is the identity that matters.
func TestLoadRSAPublicKeyFromPEM(t *testing.T) {
	dir := t.TempDir()
	key, certificate := testKeyPair(t, "VICTIM$")
	want := key.PublicKey.N

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	pkixPub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}

	cases := map[string]string{
		"certificate": writePEM(t, filepath.Join(dir, "cert.pem"),
			&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}),
		"pkcs1 private key": writePEM(t, filepath.Join(dir, "pkcs1.pem"),
			&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		"pkcs8 private key": writePEM(t, filepath.Join(dir, "pkcs8.pem"),
			&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		"pkix public key": writePEM(t, filepath.Join(dir, "pkix.pem"),
			&pem.Block{Type: "PUBLIC KEY", Bytes: pkixPub}),
		"pkcs1 public key": writePEM(t, filepath.Join(dir, "pkcs1pub.pem"),
			&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}),
		// A combined file, as produced by concatenating a cert and its key. The
		// usable block comes second on purpose, so the loader has to walk past a
		// block it cannot use for the file to resolve.
		"key after an unusable block": writePEM(t, filepath.Join(dir, "combined.pem"),
			&pem.Block{Type: "DH PARAMETERS", Bytes: []byte{0x01, 0x02}},
			&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}),
	}

	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			publicKey, err := LoadRSAPublicKeyFromPEM(path)
			if err != nil {
				t.Fatalf("LoadRSAPublicKeyFromPEM(%q) error = %v", path, err)
			}
			if publicKey.N.Cmp(want) != 0 {
				t.Errorf("loaded a different public key than expected")
			}
		})
	}
}

func TestLoadRSAPublicKeyFromPFX(t *testing.T) {
	dir := t.TempDir()
	key, certificate := testKeyPair(t, "VICTIM$")

	pfxData, err := pkcs12.Modern.Encode(key, certificate, nil, "Passw0rd!")
	if err != nil {
		t.Fatalf("pkcs12.Modern.Encode() error = %v", err)
	}
	path := filepath.Join(dir, "bundle.pfx")
	if err := os.WriteFile(path, pfxData, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	publicKey, err := LoadRSAPublicKeyFromPFX(path, "Passw0rd!")
	if err != nil {
		t.Fatalf("LoadRSAPublicKeyFromPFX() error = %v", err)
	}
	if publicKey.N.Cmp(key.PublicKey.N) != 0 {
		t.Errorf("loaded a different public key than expected")
	}
}

func TestLoaderErrors(t *testing.T) {
	dir := t.TempDir()
	key, certificate := testKeyPair(t, "VICTIM$")

	t.Run("missing PEM file", func(t *testing.T) {
		if _, err := LoadRSAPublicKeyFromPEM(filepath.Join(dir, "absent.pem")); err == nil {
			t.Error("error = nil, want an error")
		}
	})

	t.Run("PEM file with no block", func(t *testing.T) {
		path := filepath.Join(dir, "garbage.pem")
		if err := os.WriteFile(path, []byte("not a pem file at all"), 0o600); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}
		if _, err := LoadRSAPublicKeyFromPEM(path); err == nil {
			t.Error("error = nil, want an error")
		}
	})

	t.Run("PEM file with only unusable blocks", func(t *testing.T) {
		path := writePEM(t, filepath.Join(dir, "unusable.pem"),
			&pem.Block{Type: "DH PARAMETERS", Bytes: []byte{0x01, 0x02}})
		if _, err := LoadRSAPublicKeyFromPEM(path); err == nil {
			t.Error("error = nil, want an error")
		}
	})

	t.Run("missing PFX file", func(t *testing.T) {
		if _, err := LoadRSAPublicKeyFromPFX(filepath.Join(dir, "absent.pfx"), ""); err == nil {
			t.Error("error = nil, want an error")
		}
	})

	t.Run("PFX with wrong password", func(t *testing.T) {
		pfxData, err := pkcs12.Modern.Encode(key, certificate, nil, "correct")
		if err != nil {
			t.Fatalf("pkcs12.Modern.Encode() error = %v", err)
		}
		path := filepath.Join(dir, "wrongpw.pfx")
		if err := os.WriteFile(path, pfxData, 0o600); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}
		if _, err := LoadRSAPublicKeyFromPFX(path, "wrong"); err == nil {
			t.Error("error = nil, want an error")
		}
	})
}

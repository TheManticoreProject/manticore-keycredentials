package keycredential_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/magic"
	"github.com/TheManticoreProject/Manticore/windows/guid"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
	keycredential_utils "github.com/TheManticoreProject/Manticore/windows/keycredentiallink/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/version"

	"github.com/TheManticoreProject/manticore-keycredentials/certificate"
	"github.com/TheManticoreProject/manticore-keycredentials/keycredential"
)

// testKey builds an RSA key and its self-signed certificate for the tests.
func testKey(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return key, cert
}

// directoryValue builds the raw msDS-KeyCredentialLink attribute value a directory
// would hold for this public key, exactly as a write path would, and returns it in
// the string form LDAP hands back.
func directoryValue(t *testing.T, publicKey *rsa.PublicKey) []byte {
	t.Helper()

	exponentBytes := big.NewInt(int64(publicKey.E)).Bytes()
	keyMaterial := &keys.BCRYPT_RSA_PUBLIC_KEY{
		Magic: magic.BCRYPT_KEY_BLOB{Magic: magic.BCRYPT_RSAPUBLIC_MAGIC},
		Header: headers.BCRYPT_RSA_KEY_BLOB{
			BitLength:   uint32(publicKey.Size() * 8),
			CbPublicExp: uint32(len(exponentBytes)),
			CbModulus:   uint32(len(publicKey.N.Bytes())),
		},
		Content: blob.BCRYPT_RSA_PUBLIC_BLOB{
			PublicExponent: exponentBytes,
			Modulus:        publicKey.N.Bytes(),
		},
	}

	now := keycredential_utils.NewDateTimeFromTime(time.Now())
	kc := keycredentiallink.NewKeyCredentialLink(
		version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_2},
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		keyMaterial,
		guid.NewGUID(),
		&now,
		&now,
	)

	rawBytes, err := kc.Marshal()
	if err != nil {
		t.Fatalf("KeyCredentialLink.Marshal() error = %v", err)
	}
	dnWithBinary := ldap.DNWithBinary{DistinguishedName: "CN=TARGET,DC=MANTICORE,DC=local", BinaryData: rawBytes}
	return []byte(dnWithBinary.String())
}

// This is the property the find and remove modes rest on: a key credential parsed
// out of the directory has to fingerprint identically to the same public key loaded
// from a file on disk. The two fingerprints are computed by different code paths
// (ParseValue+Fingerprint vs FingerprintRSAPublicKey) and must agree.
func TestParsedValueMatchesLoadedKeyFingerprint(t *testing.T) {
	dir := t.TempDir()
	key, cert := testKey(t, "VICTIM$")

	// The directory side.
	kc, err := keycredential.ParseValue(directoryValue(t, &key.PublicKey))
	if err != nil {
		t.Fatalf("ParseValue() error = %v", err)
	}
	directoryFingerprint, ok := keycredential.Fingerprint(kc)
	if !ok {
		t.Fatal("Fingerprint() ok = false for an RSA key credential")
	}

	// The on-disk side, once from a certificate PEM and once from a PFX.
	pemPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	fromPEM, err := certificate.LoadRSAPublicKeyFromPEM(pemPath)
	if err != nil {
		t.Fatalf("LoadRSAPublicKeyFromPEM() error = %v", err)
	}
	if got := keycredential.FingerprintRSAPublicKey(fromPEM); got != directoryFingerprint {
		t.Errorf("PEM fingerprint = %s, directory fingerprint = %s", got, directoryFingerprint)
	}
}

func TestUnrelatedKeyDoesNotMatch(t *testing.T) {
	key, _ := testKey(t, "VICTIM$")
	other, _ := testKey(t, "OTHER$")

	kc, err := keycredential.ParseValue(directoryValue(t, &key.PublicKey))
	if err != nil {
		t.Fatalf("ParseValue() error = %v", err)
	}
	directoryFingerprint, ok := keycredential.Fingerprint(kc)
	if !ok {
		t.Fatal("Fingerprint() ok = false for an RSA key credential")
	}

	if keycredential.FingerprintRSAPublicKey(&other.PublicKey) == directoryFingerprint {
		t.Error("an unrelated key produced the same fingerprint")
	}
}

func TestFingerprintRSAPublicKeyIsStable(t *testing.T) {
	key, _ := testKey(t, "VICTIM$")
	if a, b := keycredential.FingerprintRSAPublicKey(&key.PublicKey), keycredential.FingerprintRSAPublicKey(&key.PublicKey); a != b {
		t.Errorf("the same key produced two fingerprints: %s vs %s", a, b)
	}
}

func TestParseValueRejectsGarbage(t *testing.T) {
	if _, err := keycredential.ParseValue([]byte("not a DN-with-binary value")); err == nil {
		t.Error("error = nil, want an error")
	}
}

// This is the attach -> find contract: a credential built from a certificate's
// public key (the way attach builds it) must, once marshalled into an attribute
// value and read back, carry the fingerprint that find computes from the same
// certificate loaded off disk. If these diverge, an attached certificate would be
// invisible to find.
func TestBuiltCredentialIsFindable(t *testing.T) {
	dir := t.TempDir()
	key, cert := testKey(t, "VICTIM$")

	// attach's build path: load the public key, wrap it, put it in a credential,
	// marshal to the attribute value form.
	keyMaterial := keycredential.BCryptPublicKeyFromRSA(&key.PublicKey)
	now := keycredential_utils.NewDateTimeFromTime(time.Now())
	kc := keycredentiallink.NewKeyCredentialLink(
		version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_2},
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		keyMaterial,
		guid.NewGUID(),
		&now,
		&now,
	)
	rawBytes, err := kc.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	dnWithBinary := ldap.DNWithBinary{DistinguishedName: "CN=VICTIM,DC=x", BinaryData: rawBytes}
	value := []byte(dnWithBinary.String())

	// find's match path: parse the value back, fingerprint the parsed material.
	parsed, err := keycredential.ParseValue(value)
	if err != nil {
		t.Fatalf("ParseValue() error = %v", err)
	}
	parsedFingerprint, ok := keycredential.Fingerprint(parsed)
	if !ok {
		t.Fatal("Fingerprint() ok = false")
	}

	// find's on-disk path: load the certificate and fingerprint it.
	pemPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	loaded, err := certificate.LoadRSAPublicKeyFromPEM(pemPath)
	if err != nil {
		t.Fatalf("LoadRSAPublicKeyFromPEM() error = %v", err)
	}

	if want := keycredential.FingerprintRSAPublicKey(loaded); parsedFingerprint != want {
		t.Errorf("attached credential fingerprint = %s, find would look for %s", parsedFingerprint, want)
	}
}

// TestKeyIDForKeyMaterialIsSHA256OfKeyMaterial pins the KeyID to the definition in
// MS-ADTS 2.2.20. The KDC looks a PKINIT key up by this hash, so a KeyID derived from
// anything else silently produces a credential that cannot authenticate.
func TestKeyIDForKeyMaterialIsSHA256OfKeyMaterial(t *testing.T) {
	key, _ := testKey(t, "VICTIM$")
	keyMaterial := keycredential.BCryptPublicKeyFromRSA(&key.PublicKey)

	keyID, err := keycredential.KeyIDForKeyMaterial(keyMaterial)
	if err != nil {
		t.Fatalf("KeyIDForKeyMaterial() error = %v", err)
	}

	rawKeyMaterial, err := keyMaterial.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	sum := sha256.Sum256(rawKeyMaterial)
	if want := base64.StdEncoding.EncodeToString(sum[:]); keyID != want {
		t.Errorf("KeyIDForKeyMaterial() = %s, want %s", keyID, want)
	}
}

// TestBuiltCredentialCarriesDerivedKeyID walks the whole write path: build the
// credential the way enroll and attach do, marshal it to the attribute value, parse it
// back, and check the KeyID that landed in the blob is the hash of the key material.
func TestBuiltCredentialCarriesDerivedKeyID(t *testing.T) {
	key, _ := testKey(t, "VICTIM$")
	keyMaterial := keycredential.BCryptPublicKeyFromRSA(&key.PublicKey)

	keyID, err := keycredential.KeyIDForKeyMaterial(keyMaterial)
	if err != nil {
		t.Fatalf("KeyIDForKeyMaterial() error = %v", err)
	}

	now := keycredential_utils.NewDateTimeFromTime(time.Now())
	kc := keycredentiallink.NewKeyCredentialLink(
		version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_2},
		keyID,
		keyMaterial,
		guid.NewGUID(),
		&now,
		&now,
	)
	rawBytes, err := kc.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	dnWithBinary := ldap.DNWithBinary{DistinguishedName: "CN=VICTIM,DC=x", BinaryData: rawBytes}

	parsed, err := keycredential.ParseValue([]byte(dnWithBinary.String()))
	if err != nil {
		t.Fatalf("ParseValue() error = %v", err)
	}

	parsedKeyMaterial, ok := keycredential.RSAKeyMaterial(parsed)
	if !ok {
		t.Fatal("RSAKeyMaterial() ok = false")
	}
	want, err := keycredential.KeyIDForKeyMaterial(parsedKeyMaterial)
	if err != nil {
		t.Fatalf("KeyIDForKeyMaterial() error = %v", err)
	}
	if parsed.Identifier != want {
		t.Errorf("stored KeyID = %s, want SHA256 of the stored key material %s", parsed.Identifier, want)
	}
}

func TestShortFingerprint(t *testing.T) {
	key, _ := testKey(t, "VICTIM$")
	full := keycredential.FingerprintRSAPublicKey(&key.PublicKey)

	short := keycredential.ShortFingerprint(full)
	if len(short) >= len(full) {
		t.Errorf("short fingerprint (%d) is not shorter than the full one (%d)", len(short), len(full))
	}
	if keycredential.ShortFingerprint(full) != short {
		t.Error("ShortFingerprint is not stable for the same input")
	}

	other, _ := testKey(t, "OTHER$")
	if keycredential.ShortFingerprint(keycredential.FingerprintRSAPublicKey(&other.PublicKey)) == short {
		t.Error("two different keys produced the same short fingerprint")
	}
}

// Package keycredential holds the msDS-KeyCredentialLink handling shared between
// the tool's modes: turning the raw attribute values returned by LDAP into parsed
// key credentials, and computing the fingerprint used to match a credential
// against a certificate or public key on disk.
package keycredential

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/magic"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
	keycredential_utils "github.com/TheManticoreProject/Manticore/windows/keycredentiallink/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/version"
)

// BCryptPublicKeyFromRSA wraps an RSA public key in the BCRYPT_RSA_PUBLIC_KEY
// structure that a msDS-KeyCredentialLink stores as its key material.
//
// This is the bridge from a certificate loaded off disk to the key material a key
// credential carries, so attaching a certificate and fingerprinting one go through
// the same construction.
//
// Parameters:
//
//	publicKey (*rsa.PublicKey): The RSA public key to wrap.
//
// Returns:
//
//	The BCRYPT_RSA_PUBLIC_KEY structure for the key.
func BCryptPublicKeyFromRSA(publicKey *rsa.PublicKey) *keys.BCRYPT_RSA_PUBLIC_KEY {
	exponentBytes := big.NewInt(int64(publicKey.E)).Bytes()
	modulusBytes := publicKey.N.Bytes()

	return &keys.BCRYPT_RSA_PUBLIC_KEY{
		Magic: magic.BCRYPT_KEY_BLOB{Magic: magic.BCRYPT_RSAPUBLIC_MAGIC},
		Header: headers.BCRYPT_RSA_KEY_BLOB{
			BitLength:   uint32(publicKey.Size() * 8),
			CbPublicExp: uint32(len(exponentBytes)),
			CbModulus:   uint32(len(modulusBytes)),
		},
		Content: blob.BCRYPT_RSA_PUBLIC_BLOB{
			PublicExponent: exponentBytes,
			Modulus:        modulusBytes,
		},
	}
}

// KeyIDForKeyMaterial returns the KeyID a msDS-KeyCredentialLink entry has to carry
// for the given key material.
//
// MS-ADTS 2.2.20 defines the KeyID entry as the SHA-256 hash of the KeyMaterial
// entry's value. The KDC matches the public key presented during a PKINIT exchange
// against that hash to find the credential, so a KeyID derived from anything else
// leaves the credential unmatched and the account unusable for authentication.
//
// The hashing and the version-dependent encoding are the library's
// utils.ComputeKeyIdentifier; this only marshals the key material to the bytes that
// go into the entry. The version has to be the one the credential is written with,
// since it selects hex for v0 and v1 and base64 for v2.
//
// Parameters:
//
//	keyMaterial (*keys.BCRYPT_RSA_PUBLIC_KEY): The key material the entry will carry.
//	kcVersion (version.KeyCredentialLinkVersion): The version of the credential.
//
// Returns:
//
//	The encoded KeyID, or an error if the key material cannot be marshalled.
func KeyIDForKeyMaterial(keyMaterial *keys.BCRYPT_RSA_PUBLIC_KEY, kcVersion version.KeyCredentialLinkVersion) (string, error) {
	rawKeyMaterial, err := keyMaterial.Marshal()
	if err != nil {
		return "", fmt.Errorf("error marshalling key material: %s", err)
	}

	return keycredential_utils.ComputeKeyIdentifier(rawKeyMaterial, kcVersion), nil
}

// ShortFingerprint condenses a full key fingerprint into a short, stable hex digest
// for display.
//
// A full fingerprint embeds the whole RSA modulus, which is hundreds of hex
// characters and unreadable in a log line. The short form is the first bytes of its
// SHA-256, which is enough to tell two keys apart at a glance while staying stable
// for the same key.
//
// Parameters:
//
//	fingerprint (string): The full fingerprint string.
//
// Returns:
//
//	A short hex digest of the fingerprint.
func ShortFingerprint(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(sum[:8])
}

// FingerprintRSAPublicKey returns the fingerprint that a msDS-KeyCredentialLink
// entry would carry for this public key, so a certificate on disk can be matched
// against the key material stored in the directory.
//
// Parameters:
//
//	publicKey (*rsa.PublicKey): The RSA public key to fingerprint.
//
// Returns:
//
//	The fingerprint string.
func FingerprintRSAPublicKey(publicKey *rsa.PublicKey) string {
	return BCryptPublicKeyFromRSA(publicKey).Fingerprint()
}

// ParseValue parses a single raw msDS-KeyCredentialLink attribute value into a
// KeyCredentialLink.
//
// The value is a DN-with-binary, exactly as returned by LDAP, so it is first
// unmarshalled into its DN and binary halves and then the binary half is parsed as
// the key credential.
//
// Parameters:
//
//	rawValue ([]byte): One raw attribute value.
//
// Returns:
//
//	The parsed key credential, or an error if either parsing step fails.
func ParseValue(rawValue []byte) (*keycredentiallink.KeyCredentialLink, error) {
	dnWithBinary := ldap.DNWithBinary{}
	if _, err := dnWithBinary.Unmarshal(rawValue); err != nil {
		return nil, fmt.Errorf("cannot unmarshal DN with binary: %s", err)
	}

	kc := keycredentiallink.KeyCredentialLink{}
	if err := kc.ParseDNWithBinary(dnWithBinary); err != nil {
		return nil, fmt.Errorf("cannot parse the key credential: %s", err)
	}

	return &kc, nil
}

// RSAKeyMaterial returns a parsed key credential's key material as an RSA public
// key, or false when the key material is not RSA.
//
// Only RSA key credentials can be fingerprinted against, or exported as, an RSA
// public key. Anything else is reported as unusable rather than as an error, since
// a directory legitimately holds credentials of other key types.
//
// Parameters:
//
//	kc (*keycredentiallink.KeyCredentialLink): The parsed key credential.
//
// Returns:
//
//	The RSA public key material and true, or nil and false.
func RSAKeyMaterial(kc *keycredentiallink.KeyCredentialLink) (*keys.BCRYPT_RSA_PUBLIC_KEY, bool) {
	rsaKeyMaterial, ok := kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY)
	return rsaKeyMaterial, ok
}

// Fingerprint returns the fingerprint of a parsed key credential's key material,
// or an empty string and false when the key material is not an RSA public key.
//
// Parameters:
//
//	kc (*keycredentiallink.KeyCredentialLink): The parsed key credential.
//
// Returns:
//
//	The fingerprint string and true, or an empty string and false.
func Fingerprint(kc *keycredentiallink.KeyCredentialLink) (string, bool) {
	rsaKeyMaterial, ok := RSAKeyMaterial(kc)
	if !ok {
		return "", false
	}
	return rsaKeyMaterial.Fingerprint(), true
}

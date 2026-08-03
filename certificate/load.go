// Package certificate holds the certificate and RSA key material handling shared
// between the tool's modes: loading it from disk, and exporting it back out.
//
// A key credential is identified by its public key, so every loader here returns a
// public key: a certificate, a private key and a public key are all usable inputs
// for the modes that need to recognise a credential.
package certificate

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// LoadRSAPublicKeyFromPFX reads a PFX file and returns the RSA public key of the
// certificate it holds.
//
// Parameters:
//
//	pathToFile (string): The path to the PFX file.
//	password (string): The password of the PFX file.
//
// Returns:
//
//	The RSA public key of the certificate, or an error if the file cannot be read,
//	decoded, or does not hold an RSA certificate.
func LoadRSAPublicKeyFromPFX(pathToFile string, password string) (*rsa.PublicKey, error) {
	pfxData, err := os.ReadFile(pathToFile)
	if err != nil {
		return nil, fmt.Errorf("error reading PFX file: %s", err)
	}

	_, certificate, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return nil, fmt.Errorf("error decoding PFX file: %s", err)
	}

	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the certificate in the PFX file does not hold an RSA public key, got %T", certificate.PublicKey)
	}

	return publicKey, nil
}

// LoadRSAPublicKeyFromPEM reads a PEM file and returns the RSA public key it leads
// to. A certificate, a private key and a public key are all usable inputs: the
// public key is derived from whichever is supplied.
//
// Every block in the file is considered, so a combined certificate-and-key PEM is
// accepted, and blocks that are not understood are skipped rather than failing the
// whole file.
//
// Parameters:
//
//	pathToFile (string): The path to the PEM file.
//
// Returns:
//
//	The RSA public key, or an error if the file cannot be read or holds no block
//	from which an RSA public key can be derived.
func LoadRSAPublicKeyFromPEM(pathToFile string) (*rsa.PublicKey, error) {
	pemData, err := os.ReadFile(pathToFile)
	if err != nil {
		return nil, fmt.Errorf("error reading PEM file: %s", err)
	}

	blockCount := 0
	for rest := pemData; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blockCount++

		if publicKey := rsaPublicKeyFromPEMBlock(block); publicKey != nil {
			return publicKey, nil
		}
	}

	if blockCount == 0 {
		return nil, fmt.Errorf("no PEM block found in '%s'", pathToFile)
	}

	return nil, fmt.Errorf("none of the %d PEM blocks in '%s' hold an RSA certificate, private key or public key", blockCount, pathToFile)
}

// rsaPublicKeyFromPEMBlock derives an RSA public key from a single PEM block, or
// returns nil when the block is not one of the understood types or does not hold
// RSA key material.
//
// Parameters:
//
//	block (*pem.Block): The PEM block to interpret.
//
// Returns:
//
//	The RSA public key, or nil.
func rsaPublicKeyFromPEMBlock(block *pem.Block) *rsa.PublicKey {
	switch block.Type {
	case "CERTIFICATE":
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		if publicKey, ok := certificate.PublicKey.(*rsa.PublicKey); ok {
			return publicKey
		}

	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		return &privateKey.PublicKey

	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		if privateKey, ok := parsed.(*rsa.PrivateKey); ok {
			return &privateKey.PublicKey
		}

	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil
		}
		if publicKey, ok := parsed.(*rsa.PublicKey); ok {
			return publicKey
		}

	case "RSA PUBLIC KEY":
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil
		}
		return publicKey
	}

	return nil
}

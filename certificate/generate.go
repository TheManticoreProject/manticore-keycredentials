package certificate

import (
	"fmt"
	"time"

	"github.com/TheManticoreProject/Manticore/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/crypto"
)

const (
	// DefaultKeySize is the RSA key size used when none is requested.
	DefaultKeySize = 2048

	// DefaultValidityDays is how long past notBefore a certificate is valid when no
	// notAfter is requested.
	DefaultValidityDays = 365
)

// ParseValidityWindow turns the notBefore and notAfter option strings into a
// certificate validity window.
//
// An empty notBefore means "now" (the underlying parser's behaviour). An empty
// notAfter defaults to DefaultValidityDays past notBefore, so a caller only has to
// supply the parts it cares about.
//
// A notAfter at or before notBefore describes a window in which the certificate is
// never valid, which is rejected rather than passed on: the certificate would be
// generated and, for enroll, attached to a target object, only to be refused
// wherever it is used.
//
// Parameters:
//
//	notBefore (string): The start of the validity window, or empty for now.
//	notAfter (string): The end of the validity window, or empty for the default.
//
// Returns:
//
//	The notBefore and notAfter times, or an error if either string is malformed or
//	the window is empty.
func ParseValidityWindow(notBefore, notAfter string) (time.Time, time.Time, error) {
	notBeforeTime, err := utils.TimeStringToTime(notBefore)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("error parsing notBefore: %s", err)
	}

	notAfterTime := notBeforeTime.Add(time.Hour * 24 * DefaultValidityDays)
	if len(notAfter) > 0 {
		notAfterTimePtr, err := utils.TimeStringToTime(notAfter)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("error parsing notAfter: %s", err)
		}
		notAfterTime = *notAfterTimePtr
	}

	if !notAfterTime.After(*notBeforeTime) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"notAfter (%s) has to be after notBefore (%s), otherwise the certificate is never valid",
			notAfterTime.Format(time.RFC3339), notBeforeTime.Format(time.RFC3339),
		)
	}

	return *notBeforeTime, notAfterTime, nil
}

// Generate creates a self-signed RSA certificate for the given subject.
//
// A key size of zero selects DefaultKeySize, so callers can pass an unset option
// through unchanged.
//
// Parameters:
//
//	subject (string): The common name of the certificate subject.
//	keySize (int): The RSA key size, or zero for the default.
//	notBefore (time.Time): The start of the validity window.
//	notAfter (time.Time): The end of the validity window.
//
// Returns:
//
//	The generated certificate, or an error if generation fails.
func Generate(subject string, keySize int, notBefore, notAfter time.Time) (*crypto.X509Certificate, error) {
	if keySize == 0 {
		keySize = DefaultKeySize
	}

	cert, err := crypto.NewX509Certificate(subject, keySize, notBefore, notAfter)
	if err != nil {
		return nil, fmt.Errorf("error creating X509Certificate: %s", err)
	}

	return cert, nil
}

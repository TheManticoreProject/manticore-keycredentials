package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"shadowcredentials/keycredentiallink/key"
	"math/rand"
	"strings"
	"time"
)

// ConvertToBinaryIdentifier converts a key identifier string to its binary representation.
//
// Parameters:
//
// - keyIdentifier: A string representing the key identifier to be converted.
//
// - version: A KeyCredentialVersion object representing the version of the key credential.
//
// Returns:
//
// - A byte slice containing the binary representation of the key identifier.
//
// - An error if the conversion fails.
//
// Note:
//
// The function handles different versions of key credentials as follows:
//
// - For version 0 and 1, the key identifier is expected to be in hexadecimal format and is decoded using hex.DecodeString.
//
// - For version 2, the key identifier is expected to be in base64 format and is decoded using base64.StdEncoding.DecodeString with padding.
//
// - For any other version, the key identifier is treated as base64 format and is decoded using base64.StdEncoding.DecodeString with padding.
func ConvertToBinaryIdentifier(keyIdentifier string, version key.KeyCredentialVersion) ([]byte, error) {
	switch version.Value {
	case key.KeyCredentialVersion_0, key.KeyCredentialVersion_1:
		return hex.DecodeString(keyIdentifier)
	case key.KeyCredentialVersion_2:
		return base64.StdEncoding.DecodeString(strings.TrimRight(keyIdentifier, "=") + "=")
	default:
		return base64.StdEncoding.DecodeString(strings.TrimRight(keyIdentifier, "=") + "=")
	}
}

// ConvertFromBinaryIdentifier converts a binary key identifier to its string representation.
//
// Parameters:
// - keyIdentifier: A byte slice containing the binary representation of the key identifier.
// - version: A KeyCredentialVersion object representing the version of the key credential.
//
// Returns:
// - A string representing the key identifier.
//
// Note:
// The function handles different versions of key credentials as follows:
// - For version 0 and 1, the key identifier is encoded to a hexadecimal string using hex.EncodeToString.
// - For version 2, the key identifier is encoded to a base64 string using base64.StdEncoding.EncodeToString.
// - For any other version, the key identifier is treated as base64 format and is encoded using base64.StdEncoding.EncodeToString.
func ConvertFromBinaryIdentifier(keyIdentifier []byte, version key.KeyCredentialVersion) string {
	switch version.Value {
	case key.KeyCredentialVersion_0, key.KeyCredentialVersion_1:
		return hex.EncodeToString(keyIdentifier)
	case key.KeyCredentialVersion_2:
		return base64.StdEncoding.EncodeToString(keyIdentifier)
	default:
		return base64.StdEncoding.EncodeToString(keyIdentifier)
	}
}

// ConvertFromBinaryTime converts a binary representation of time to a time.Time object.
// The binary representation is expected to be in little-endian format.
//
// Parameters:
// - rawBinaryTime: A byte slice containing the binary representation of the time.
// - source: The source of the key, which can affect the interpretation of the time.
// - version: The version of the KeyCredential, which can affect the interpretation of the time.
//
// Returns:
// - A time.Time object representing the converted time.
//
// Note:
// The function currently treats all versions and sources the same way, converting the binary
// timestamp directly to a Unix time in nanoseconds.
//
// Src : https://github.com/microsoft/referencesource/blob/master/mscorlib/system/datetime.cs
func ConvertFromBinaryTime(rawBinaryTime []byte, source key.KeySource, version key.KeyCredentialVersion) DateTime {
	timeStamp := binary.LittleEndian.Uint64(rawBinaryTime)

	switch version.Value {
	case key.KeyCredentialVersion_0, key.KeyCredentialVersion_1:
		return NewDateTimeFromUnixTimeStamp(uint64(timeStamp))
	case key.KeyCredentialVersion_2:
		if source == key.KeySource_AD {
			return NewDateTimeFromUnixTimeStamp(uint64(timeStamp))
		} else {
			// This is not fully supported right now, you may encounter issues.
			return NewDateTimeFromUnixTimeStamp(uint64(timeStamp))
		}
	default:
		if source == key.KeySource_AD {
			return NewDateTimeFromUnixTimeStamp(uint64(timeStamp))
		} else {
			// This is not fully supported right now, you may encounter issues.
			return NewDateTimeFromUnixTimeStamp(uint64(timeStamp))
		}
	}
}

// ConvertToBinaryTime converts a time.Time object to its binary representation in little-endian format.
//
// Parameters:
// - date: A time.Time object representing the time to be converted.
// - source: The source of the key, which can affect the interpretation of the time.
// - version: The version of the KeyCredential, which can affect the interpretation of the time.
//
// Returns:
// - A byte slice containing the binary representation of the time in little-endian format.
//
// Note:
// The function currently treats all versions and sources the same way, converting the time
// directly to a Unix time in nanoseconds and then encoding it in little-endian format.
func ConvertToBinaryTime(date time.Time, source key.KeySource, version key.KeyCredentialVersion) []byte {
	timeStamp := date.UnixNano()

	switch version.Value {
	case key.KeyCredentialVersion_0, key.KeyCredentialVersion_1:
		return binary.LittleEndian.AppendUint64(nil, uint64(timeStamp))
	case key.KeyCredentialVersion_2:
		if source == key.KeySource_AD {
			return binary.LittleEndian.AppendUint64(nil, uint64(timeStamp))
		} else {
			return binary.LittleEndian.AppendUint64(nil, uint64(timeStamp))
		}
	default:
		if source == key.KeySource_AD {
			return binary.LittleEndian.AppendUint64(nil, uint64(timeStamp))
		} else {
			return binary.LittleEndian.AppendUint64(nil, uint64(timeStamp))
		}
	}
}

// ComputeHash calculates the SHA-256 hash of the provided data.
//
// Parameters:
// - data: A byte slice containing the input data to be hashed.
//
// Returns:
// - A byte slice containing the SHA-256 hash of the input data.
//
// Note:
// This function uses the SHA-256 hashing algorithm from the crypto/sha256 package to generate a fixed-size
// 32-byte hash. The resulting hash can be used for various purposes, such as data integrity verification
// and cryptographic operations.
func ComputeHash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// ComputeKeyIdentifier generates a key identifier based on the provided key material and version.
//
// Parameters:
// - keyMaterial: A byte slice containing the key material to be used for generating the key identifier.
// - version: A key.KeyCredentialVersion value representing the version of the key credential.
//
// Returns:
// - A string representing the generated key identifier.
//
// Note:
// This function first computes the SHA-256 hash of the provided key material using the ComputeHash function.
// It then converts the resulting binary hash to a string representation based on the specified version
// using the ConvertFromBinaryIdentifier function. The generated key identifier can be used for various
// purposes, such as uniquely identifying cryptographic keys and credentials.
func ComputeKeyIdentifier(keyMaterial []byte, version key.KeyCredentialVersion) string {
	binaryId := ComputeHash(keyMaterial)
	return ConvertFromBinaryIdentifier(binaryId, version)
}

// TimeParseOrNow parses a time string or returns the current time if the string is empty.
//
// Parameters:
// - timeString: A string representing the time to be parsed.
//
// Returns:
// - A pointer to a time.Time object representing the parsed time or the current time if the string is empty.
// - An error if the time string is not valid.
func TimeParseOrNow(timeString string) (time.Time, error) {
	if timeString == "" {
		t := time.Now()
		return t, nil
	} else {
		t, err := time.Parse(time.RFC3339, timeString)
		if err != nil {
			t := time.Now()
			return t, err
		}
		return t, nil
	}
}

// RandomString generates a random string of the specified length.
//
// Parameters:
// - length: The length of the random string to generate.
//
// Returns:
// - A string of the specified length.
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}

// PathSafeString returns a string that is safe to use in file paths by replacing unsafe characters.
//
// Parameters:
// - input: The input string to be sanitized.
//
// Returns:
// - A string that is safe to use in file paths.
func PathSafeString(input string) string {
	unsafeChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", " ", "\n", "\r", "\t", "\v", "\f", "\b", " "}
	safeString := input
	for _, char := range unsafeChars {
		safeString = strings.ReplaceAll(safeString, char, "_")
	}
	return safeString
}

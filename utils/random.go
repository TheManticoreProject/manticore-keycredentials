package utils

import "math/rand"

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

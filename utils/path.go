package utils

import "strings"

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

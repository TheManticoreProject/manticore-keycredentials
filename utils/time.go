package utils

import "time"

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

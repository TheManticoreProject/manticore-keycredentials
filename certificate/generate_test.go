package certificate

import (
	"testing"
	"time"
)

// A notAfter at or before notBefore describes a window the certificate is never valid
// in. Accepting it silently produces a certificate that is refused wherever it is
// used, and enroll would attach the matching credential to a target object first.
func TestParseValidityWindowRejectsEmptyWindow(t *testing.T) {
	tests := []struct {
		name      string
		notBefore string
		notAfter  string
	}{
		{"notAfter before notBefore", "2027-01-01T00:00:00Z", "2026-01-01T00:00:00Z"},
		{"notAfter equal to notBefore", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"},
		{"notAfter one second before notBefore", "2026-01-01T00:00:01Z", "2026-01-01T00:00:00Z"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := ParseValidityWindow(test.notBefore, test.notAfter); err == nil {
				t.Errorf("ParseValidityWindow(%q, %q) error = nil, want an error", test.notBefore, test.notAfter)
			}
		})
	}
}

func TestParseValidityWindowAcceptsOrderedWindow(t *testing.T) {
	notBefore, notAfter, err := ParseValidityWindow("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ParseValidityWindow() error = %v", err)
	}
	if want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); !notBefore.Equal(want) {
		t.Errorf("notBefore = %s, want %s", notBefore, want)
	}
	if want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC); !notAfter.Equal(want) {
		t.Errorf("notAfter = %s, want %s", notAfter, want)
	}
}

// The defaults have to stay usable: both empty means "now" for DefaultValidityDays,
// and an explicit notBefore alone still gets the default span added to it. Neither
// may trip the new ordering check.
func TestParseValidityWindowDefaults(t *testing.T) {
	notBefore, notAfter, err := ParseValidityWindow("", "")
	if err != nil {
		t.Fatalf("ParseValidityWindow(\"\", \"\") error = %v", err)
	}
	if got := notAfter.Sub(notBefore); got != time.Hour*24*DefaultValidityDays {
		t.Errorf("default validity span = %s, want %s", got, time.Hour*24*DefaultValidityDays)
	}

	notBefore, notAfter, err = ParseValidityWindow("2026-01-01T00:00:00Z", "")
	if err != nil {
		t.Fatalf("ParseValidityWindow() error = %v", err)
	}
	if got := notAfter.Sub(notBefore); got != time.Hour*24*DefaultValidityDays {
		t.Errorf("validity span from an explicit notBefore = %s, want %s", got, time.Hour*24*DefaultValidityDays)
	}
}

func TestParseValidityWindowRejectsMalformedTimes(t *testing.T) {
	if _, _, err := ParseValidityWindow("2026-01-01", ""); err == nil {
		t.Error("ParseValidityWindow() with a non-RFC3339 notBefore: error = nil, want an error")
	}
	if _, _, err := ParseValidityWindow("", "2027-01-01"); err == nil {
		t.Error("ParseValidityWindow() with a non-RFC3339 notAfter: error = nil, want an error")
	}
}

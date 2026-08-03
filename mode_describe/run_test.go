package mode_describe

import (
	"strings"
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/windows/guid"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/crypto"
	keycredential_utils "github.com/TheManticoreProject/Manticore/windows/keycredentiallink/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/version"
)

// builtCredential constructs a real KeyCredentialLink from a freshly generated RSA
// certificate, the same way a write path would, so credentialLines can be checked
// against a credential whose fields are actually populated.
func builtCredential(t *testing.T) *keycredentiallink.KeyCredentialLink {
	t.Helper()

	now := time.Now()
	cert, err := crypto.NewX509Certificate("VICTIM$", 2048, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewX509Certificate() error = %v", err)
	}
	pub, err := cert.ExportRSAPublicKeyBCrypt()
	if err != nil {
		t.Fatalf("ExportRSAPublicKeyBCrypt() error = %v", err)
	}

	dt := keycredential_utils.NewDateTimeFromTime(now)
	return keycredentiallink.NewKeyCredentialLink(
		version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_2},
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		pub,
		guid.NewGUID(),
		&dt,
		&dt,
	)
}

func TestCredentialLines(t *testing.T) {
	lines := credentialLines(builtCredential(t))
	joined := strings.Join(lines, "\n")

	// The mandatory fields always render. "2048" and "bits" are checked separately
	// because an ANSI reset sits between them in the rendered line.
	for _, want := range []string{"Version:", "Usage:", "KeySize:", "2048", "bits"} {
		if !strings.Contains(joined, want) {
			t.Errorf("credentialLines() output missing %q; got:\n%s", want, joined)
		}
	}

	// The timestamps supplied above render, and a device id is always present since
	// NewKeyCredentialLink is given one.
	for _, want := range []string{"CreationTime", "LastLogonTime", "DeviceId"} {
		if !strings.Contains(joined, want) {
			t.Errorf("credentialLines() output missing %q; got:\n%s", want, joined)
		}
	}
}

func TestCredentialLinesOmitsAbsentOptionalFields(t *testing.T) {
	kc := builtCredential(t)
	// Clear the optional pointer fields; their lines must then not appear.
	kc.Source = nil
	kc.DeviceId = nil
	kc.CreationTime = nil
	kc.LastLogonTime = nil
	kc.LegacyUsage = ""

	joined := strings.Join(credentialLines(kc), "\n")

	for _, absent := range []string{"Source:", "DeviceId:", "CreationTime", "LastLogonTime", "LegacyUsage"} {
		if strings.Contains(joined, absent) {
			t.Errorf("credentialLines() included %q for a credential that does not carry it; got:\n%s", absent, joined)
		}
	}
	// The mandatory fields are still there.
	if !strings.Contains(joined, "Version:") || !strings.Contains(joined, "Usage:") {
		t.Errorf("credentialLines() dropped a mandatory field; got:\n%s", joined)
	}
}

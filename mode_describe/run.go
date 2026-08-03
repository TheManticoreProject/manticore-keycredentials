package mode_describe

import (
	"encoding/hex"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"

	"github.com/TheManticoreProject/manticore-keycredentials/config"
	"github.com/TheManticoreProject/manticore-keycredentials/keycredential"
	"github.com/TheManticoreProject/manticore-keycredentials/utils"
)

// timeLayout renders a credential's timestamps. The values are stored as UTC
// FILETIMEs, so they are formatted from their universal time to match the "(UTC)"
// label, rather than in the host's local zone.
const timeLayout = "2006-01-02 15:04:05"

// Run decodes and displays the KeyCredentialLink values of a target object.
//
// Unlike list, which prints the raw attribute values, describe parses each value
// and renders its fields: version, key identifier, key hash and its integrity,
// usage, source, device id, and timestamps.
//
// Parameters:
//
//	distinguishedName (string): The distinguished name of the target object.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(distinguishedName string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'describe'")
	}

	ldapSession, err := utils.NewLDAPSession(
		config.Network.DomainController,
		config.Network.LDAP.LDAPPort,
		config.Credentials,
		config.Network.LDAP.UseLdaps,
		config.Network.LDAP.UseKerberos,
		config.Network.LDAP.SPNHostname,
	)
	if err != nil {
		return err
	}
	if config.Debug {
		utils.LogConnection(config.Network.Domain, config.Credentials.Username, config.Network.DomainController, config.Network.LDAP.LDAPPort, config.Network.LDAP.UseLdaps)
	}

	attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
	entry, err := utils.FindUniqueObject(ldapSession, distinguishedName, attributes, config.Debug)
	if err != nil {
		return err
	}

	rawValues := entry.GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink")
	if len(rawValues) == 0 {
		logger.Print(fmt.Sprintf("[>] KeyCredentialLink values of \x1b[94m%s\x1b[0m (0)", distinguishedName))
		return nil
	}

	logger.Print(fmt.Sprintf("[>] KeyCredentialLink values of \x1b[94m%s\x1b[0m (\x1b[93m%d\x1b[0m):", distinguishedName, len(rawValues)))
	for k, rawValue := range rawValues {
		lastCredential := k == len(rawValues)-1

		kc, err := keycredential.ParseValue(rawValue)
		if err != nil {
			// A value that cannot be parsed is reported in place rather than
			// aborting the whole object, so the other credentials still display.
			describeBranch(lastCredential, fmt.Sprintf("[%d] \x1b[91munparsable value\x1b[0m: %s", k+1, err))
			continue
		}

		describeBranch(lastCredential, fmt.Sprintf("[%d] KeyID: \x1b[94m%s\x1b[0m", k+1, kc.Identifier))

		indent := "  │   "
		if lastCredential {
			indent = "      "
		}

		lines := credentialLines(kc)
		for i, line := range lines {
			if i < len(lines)-1 {
				logger.Print(fmt.Sprintf("%s├── %s", indent, line))
			} else {
				logger.Print(fmt.Sprintf("%s└── %s", indent, line))
			}
		}
	}
	logger.Print("")

	return nil
}

// describeBranch prints the top-level branch line for one credential, choosing the
// last-item glyph when it is the final credential of the object.
func describeBranch(last bool, text string) {
	if last {
		logger.Print(fmt.Sprintf("  └── %s", text))
	} else {
		logger.Print(fmt.Sprintf("  ├── %s", text))
	}
}

// credentialLines builds the detail lines shown under one credential. Optional
// fields are only included when present, so the output reflects what the credential
// actually carries.
func credentialLines(kc *keycredentiallink.KeyCredentialLink) []string {
	lines := []string{
		fmt.Sprintf("Version: \x1b[93m%s\x1b[0m", kc.Version.String()),
	}

	if len(kc.KeyHash) > 0 {
		verdict := "\x1b[91minvalid\x1b[0m"
		if kc.CheckIntegrity() {
			verdict = "\x1b[92mvalid\x1b[0m"
		}
		lines = append(lines, fmt.Sprintf("KeyHash: \x1b[93m%s\x1b[0m (%s)", hex.EncodeToString(kc.KeyHash), verdict))
	}

	if rsa, ok := keycredential.RSAKeyMaterial(kc); ok {
		lines = append(lines, fmt.Sprintf("KeySize: \x1b[93m%d\x1b[0m bits", rsa.Header.BitLength))
	}

	lines = append(lines, fmt.Sprintf("Usage: \x1b[93m%s\x1b[0m", kc.Usage.String()))

	if len(kc.LegacyUsage) > 0 {
		lines = append(lines, fmt.Sprintf("LegacyUsage: \x1b[93m%s\x1b[0m", kc.LegacyUsage))
	}
	if kc.Source != nil {
		lines = append(lines, fmt.Sprintf("Source: \x1b[93m%s\x1b[0m", kc.Source.String()))
	}
	if kc.DeviceId != nil {
		lines = append(lines, fmt.Sprintf("DeviceId: \x1b[93m%s\x1b[0m", kc.DeviceId.ToFormatD()))
	}
	if kc.CreationTime != nil {
		lines = append(lines, fmt.Sprintf("CreationTime (UTC): \x1b[93m%s\x1b[0m", kc.CreationTime.ToUniversalTime().Format(timeLayout)))
	}
	if kc.LastLogonTime != nil {
		lines = append(lines, fmt.Sprintf("LastLogonTime (UTC): \x1b[93m%s\x1b[0m", kc.LastLogonTime.ToUniversalTime().Format(timeLayout)))
	}

	return lines
}

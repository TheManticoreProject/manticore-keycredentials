package mode_attach

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/utils"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	"github.com/TheManticoreProject/Manticore/windows/guid"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
	keycredential_utils "github.com/TheManticoreProject/Manticore/windows/keycredentiallink/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/version"

	"github.com/TheManticoreProject/manticore-keycredentials/certificate"
	"github.com/TheManticoreProject/manticore-keycredentials/cli"
	"github.com/TheManticoreProject/manticore-keycredentials/config"
	"github.com/TheManticoreProject/manticore-keycredentials/keycredential"
	kcl_utils "github.com/TheManticoreProject/manticore-keycredentials/utils"
)

// Run attaches an existing certificate to one or more target objects as a
// KeyCredentialLink.
//
// The same certificate is attached to every target. When an identifier or device
// id is not given, a fresh one is generated per object, so the objects do not share
// a credential identifier even though they share a key.
//
// Parameters:
//
//	targets (cli.TargetOptions): The target selection flags.
//	safety (cli.SafetyOptions): The confirmation flag.
//	pfxCertificate (string): Path to a PFX file holding the certificate to attach.
//	pfxPassword (string): Password of the PFX file.
//	pemFile (string): Path to a PEM file holding the certificate to attach.
//	identifier (string): The identifier of the KeyCredential, per-object random when empty.
//	creationTime (string): The creation time of the KeyCredential, now when empty.
//	lastLogonTime (string): The last logon time of the KeyCredential, now when empty.
//	deviceId (string): The device id of the KeyCredential, per-object random when empty.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, or if any target could not be modified.
func Run(targets cli.TargetOptions, safety cli.SafetyOptions, pfxCertificate, pfxPassword, pemFile, identifier, creationTime, lastLogonTime, deviceId string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'attach'")
	}

	if err := cli.CheckRemovedSafetyFlags(os.Args); err != nil {
		return err
	}

	var publicKey *rsa.PublicKey
	var err error
	if len(pfxCertificate) > 0 {
		publicKey, err = certificate.LoadRSAPublicKeyFromPFX(pfxCertificate, pfxPassword)
	} else {
		publicKey, err = certificate.LoadRSAPublicKeyFromPEM(pemFile)
	}
	if err != nil {
		return err
	}
	keyMaterial := keycredential.BCryptPublicKeyFromRSA(publicKey)

	// Validate the explicitly-supplied metadata once, before connecting, so a bad
	// value fails fast rather than after resolving targets.
	if len(identifier) > 0 {
		identifierBytes, err := base64.StdEncoding.DecodeString(identifier)
		if err != nil {
			return fmt.Errorf("error decoding identifier: %s", err)
		}
		if len(identifierBytes) != 32 {
			return fmt.Errorf("identifier must be 32 bytes data encoded in base64")
		}
	}
	if len(deviceId) > 0 {
		if _, err := guid.FromString(deviceId); err != nil {
			return fmt.Errorf("error parsing deviceId: %s", err)
		}
	}
	creationDateTime, err := parseTimeOrNow(creationTime)
	if err != nil {
		return fmt.Errorf("error parsing creationTime: %s", err)
	}
	lastLogonDateTime, err := parseTimeOrNow(lastLogonTime)
	if err != nil {
		return fmt.Errorf("error parsing lastLogonTime: %s", err)
	}

	if err := cli.ValidateTargets(targets); err != nil {
		return err
	}

	ldapSession, err := kcl_utils.NewLDAPSession(
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
		kcl_utils.LogConnection(config.Network.Domain, config.Credentials.Username, config.Network.DomainController, config.Network.LDAP.LDAPPort, config.Network.LDAP.UseLdaps)
	}

	attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
	entries, err := cli.ResolveTargets(ldapSession, targets, attributes, config.Debug)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		logger.Info("No target object resolved; nothing to do.")
		return nil
	}

	logger.Print(fmt.Sprintf("[>] Attaching the certificate (fingerprint \x1b[93m%s\x1b[0m) to (\x1b[93m%d\x1b[0m):", keycredential.ShortFingerprint(keyMaterial.Fingerprint()), len(entries)))
	for k, entry := range entries {
		glyph := "├──"
		if k == len(entries)-1 {
			glyph = "└──"
		}
		logger.Print(fmt.Sprintf("  %s \x1b[94m%s\x1b[0m", glyph, entry.GetAttributeValue("distinguishedName")))
	}
	logger.Print("")

	if !cli.ConfirmWrite("attach the certificate to", len(entries), safety) {
		return nil
	}

	// One version value feeds both the KeyID derivation and the credential itself, so
	// the identifier encoding cannot drift from the version it is written under. The
	// key material is the same for every target, so the derived KeyID is too.
	kcVersion := version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_2}

	failures := 0
	for _, entry := range entries {
		dn := entry.GetAttributeValue("distinguishedName")

		perObjectIdentifier, err := resolveIdentifier(identifier, keyMaterial, kcVersion)
		if err != nil {
			failures++
			logger.Warn(fmt.Sprintf("%s: %s", dn, err))
			continue
		}
		perObjectDeviceId := guid.NewGUID()
		if len(deviceId) > 0 {
			perObjectDeviceId, _ = guid.FromString(deviceId)
		}

		kc := keycredentiallink.NewKeyCredentialLink(
			kcVersion,
			perObjectIdentifier,
			keyMaterial,
			perObjectDeviceId,
			&lastLogonDateTime,
			&creationDateTime,
		)

		rawBytes, err := kc.Marshal()
		if err != nil {
			failures++
			logger.Warn(fmt.Sprintf("%s: error converting KeyCredential to raw bytes: %s", dn, err))
			continue
		}

		dnWithBinary := ldap.DNWithBinary{DistinguishedName: dn, BinaryData: rawBytes}
		if err := ldapSession.AddStringToAttributeList(dn, "msDS-KeyCredentialLink", dnWithBinary.String()); err != nil {
			failures++
			logger.Warn(fmt.Sprintf("%s: %s", dn, err))
			continue
		}
		logger.Info(fmt.Sprintf("Attached the certificate to '%s'", dn))
	}

	if failures > 0 {
		return fmt.Errorf("failed to attach to %d of %d object(s)", failures, len(entries))
	}

	return nil
}

// resolveIdentifier returns the explicit identifier when one was given, or the
// KeyID the key material requires.
//
// Parameters:
//
//	identifier (string): The explicit identifier, or empty to derive it.
//	keyMaterial (*keys.BCRYPT_RSA_PUBLIC_KEY): The key material of the credential.
//
// Returns:
//
//	The identifier to use, or an error if the KeyID cannot be derived.
func resolveIdentifier(identifier string, keyMaterial *keys.BCRYPT_RSA_PUBLIC_KEY, kcVersion version.KeyCredentialLinkVersion) (string, error) {
	if len(identifier) > 0 {
		return identifier, nil
	}
	return keycredential.KeyIDForKeyMaterial(keyMaterial, kcVersion)
}

// parseTimeOrNow parses an option time string, defaulting to now when it is empty.
//
// Parameters:
//
//	value (string): The time string, or empty for now.
//
// Returns:
//
//	The parsed DateTime, or an error if the string is malformed.
func parseTimeOrNow(value string) (keycredential_utils.DateTime, error) {
	t, err := utils.TimeStringToTime(value)
	if err != nil {
		return keycredential_utils.DateTime{}, err
	}
	return keycredential_utils.NewDateTimeFromTime(*t), nil
}

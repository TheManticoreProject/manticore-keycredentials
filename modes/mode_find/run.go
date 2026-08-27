package mode_find

import (
	"crypto/rsa"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ldapv3 "github.com/go-ldap/ldap/v3"

	"github.com/TheManticoreProject/manticore-keycredentials/certificate"
	"github.com/TheManticoreProject/manticore-keycredentials/config"
	"github.com/TheManticoreProject/manticore-keycredentials/keycredential"
	"github.com/TheManticoreProject/manticore-keycredentials/utils"
)

// match is one msDS-KeyCredentialLink entry whose key material is the key that was
// searched for.
type match struct {
	distinguishedName string
	deviceId          string
	creationTime      string
}

// Run finds the objects that have a given key credential set.
//
// The key is identified by its public key, which is the only part of a key
// credential the directory stores. A certificate, a private key or a public key are
// therefore all usable inputs.
//
// Parameters:
//
//	distinguishedName (string): The distinguished name of a single object to check.
//	  When empty, every object holding a msDS-KeyCredentialLink is searched.
//	pfxCertificate (string): Path to a PFX file holding the certificate to look for.
//	pfxPassword (string): Password of the PFX file.
//	pemFile (string): Path to a PEM file holding the certificate, private key or
//	  public key to look for.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(distinguishedName string, pfxCertificate string, pfxPassword string, pemFile string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'find'")
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

	wantedFingerprint := keycredential.FingerprintRSAPublicKey(publicKey)
	if config.Debug {
		logger.Debug(fmt.Sprintf("Searching for key fingerprint: %s", wantedFingerprint))
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

	// Only objects that actually hold a key credential are worth parsing, so the
	// attribute presence filter is kept even when a single object is targeted.
	query := "(msDS-KeyCredentialLink=*)"
	if len(distinguishedName) > 0 {
		safeDN := ldapv3.EscapeFilter(distinguishedName)
		query = fmt.Sprintf("(&(distinguishedName=%s)(msDS-KeyCredentialLink=*))", safeDN)
	}
	if config.Debug {
		logger.Debug(fmt.Sprintf("Querying ldap: %s", query))
	}

	attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
	ldapResults, err := ldapSession.QueryWholeSubtree("", query, attributes)
	if err != nil {
		return fmt.Errorf("error querying LDAP server: %s", err)
	}

	if config.Debug {
		logger.Debug(fmt.Sprintf("Parsing the key credentials of %d objects", len(ldapResults)))
	}

	matches := []match{}
	compared, skipped := 0, 0

	for _, entry := range ldapResults {
		entryDN := entry.GetAttributeValue("distinguishedName")

		for _, rawValue := range entry.GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink") {
			kc, err := keycredential.ParseValue(rawValue)
			if err != nil {
				skipped++
				if config.Debug {
					logger.Debug(fmt.Sprintf("Skipping a value of '%s', %s", entryDN, err))
				}
				continue
			}

			// Only RSA key credentials can match an RSA public key. Anything else is
			// not a failure, it simply cannot be the key being searched for.
			fingerprint, ok := keycredential.Fingerprint(kc)
			if !ok {
				skipped++
				if config.Debug {
					logger.Debug(fmt.Sprintf("Skipping a value of '%s', key material is %T and not an RSA public key", entryDN, kc.KeyMaterial))
				}
				continue
			}

			compared++
			if fingerprint != wantedFingerprint {
				continue
			}

			found := match{distinguishedName: entryDN}
			if kc.DeviceId != nil {
				found.deviceId = kc.DeviceId.ToFormatD()
			}
			if kc.CreationTime != nil {
				// Stored as a UTC FILETIME; render it as UTC to match the label.
				found.creationTime = kc.CreationTime.ToUniversalTime().Format("2006-01-02 15:04:05")
			}
			matches = append(matches, found)
		}
	}

	if config.Debug {
		logger.Debug(fmt.Sprintf("Compared %d key credentials, skipped %d", compared, skipped))
	}

	if len(matches) == 0 {
		logger.Print("[>] Objects with this key credential (0)")
		return nil
	}

	logger.Print(fmt.Sprintf("[>] Objects with this key credential (\x1b[93m%d\x1b[0m):", len(matches)))
	for k, found := range matches {
		lastMatch := k == len(matches)-1

		if lastMatch {
			logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m", found.distinguishedName))
		} else {
			logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m", found.distinguishedName))
		}

		// The branch of the parent object has to be carried down while it still has
		// siblings below it.
		indent := "  │   "
		if lastMatch {
			indent = "      "
		}

		if len(found.deviceId) > 0 {
			logger.Print(fmt.Sprintf("%s├── DeviceId: \x1b[93m%s\x1b[0m", indent, found.deviceId))
		}
		if len(found.creationTime) > 0 {
			logger.Print(fmt.Sprintf("%s└── CreationTime (UTC): \x1b[93m%s\x1b[0m", indent, found.creationTime))
		}
	}
	logger.Print("")

	return nil
}

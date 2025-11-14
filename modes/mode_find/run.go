package mode_find

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"

	"github.com/TheManticoreProject/KeyCredentialLink/config"
)

// Run finds a KeyCredentialLink in an object.
//
// Parameters:
// - distinguishedName: The distinguished name of the object.
// - identifier: The identifier of the KeyCredential.
// - config: The configuration of the application.
//
// Returns:
// - An error if the operation fails.
// - nil if the operation succeeds.
func Run(distinguishedName string, identifier string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'find'")
	}

	ldapSession, err := ldap.NewSession(
		config.Network.DomainController,
		config.Network.LDAP.LDAPPort,
		config.Credentials,
		config.Network.LDAP.UseLdaps,
		false,
	)
	if err != nil {
		return fmt.Errorf("error creating LDAP session: %s", err)
	}

	connected, err := ldapSession.Connect()
	if err != nil {
		return fmt.Errorf("error connecting to LDAP server: %s", err)
	}

	if connected {
		query := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
		attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
		ldapResults, err := ldapSession.QueryWholeSubtree("", query, attributes)
		if err != nil {
			return fmt.Errorf("error querying LDAP server: %s", err)
		}

		if len(ldapResults) == 0 {
			logger.Warn(fmt.Sprintf("No objects with distinguishedName '%s' found.", distinguishedName))
			return fmt.Errorf("no objects with distinguishedName '%s' found", distinguishedName)
		}

		if len(ldapResults) > 1 {
			logger.Warn(fmt.Sprintf("More than one object with distinguishedName '%s' found (%d).", distinguishedName, len(ldapResults)))
			return fmt.Errorf("more than one object with distinguishedName '%s' found (%d)", distinguishedName, len(ldapResults))
		}

		msDSKeyCredentialLinkValues := ldapResults[0].GetAttributeValues("msDS-KeyCredentialLink")
		logger.Info(fmt.Sprintf("Found %d msDS-KeyCredentialLink values for '%s'", len(msDSKeyCredentialLinkValues), distinguishedName))
		for k, msdskcl := range msDSKeyCredentialLinkValues {
			logger.Info(fmt.Sprintf("(%d/%d): %s", k+1, len(msDSKeyCredentialLinkValues), msdskcl))
		}

		for k, msdskcl := range msDSKeyCredentialLinkValues {
			logger.Info(fmt.Sprintf("(%d/%d): %s", k+1, len(msDSKeyCredentialLinkValues), msdskcl))
		}
	}

	return nil
}

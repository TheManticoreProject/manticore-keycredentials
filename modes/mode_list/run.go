package mode_list

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"

	"github.com/TheManticoreProject/ShadowCredentials/config"
)

// Run lists all KeyCredentials for a given user.
//
// Parameters:
// - distinguishedName: The distinguished name of the user.
// - config: The configuration of the application.
func Run(distinguishedName string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'list'")
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

			query := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)

			attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
			ldapResults, err := ldapSession.QueryWholeSubtree(query, "", attributes)
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

			msDSKeyCredentialLinkValues := ldapResults[0].GetAttributeValues("msDS-KeyCredentialLink")
			for k, msdskcl := range msDSKeyCredentialLinkValues {
				logger.Info(fmt.Sprintf("(%d/%d): %s", k+1, len(msDSKeyCredentialLinkValues), msdskcl))
			}
		}
	} else {
		return fmt.Errorf("error connecting to LDAP server")
	}

	return nil
}

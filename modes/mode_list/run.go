package mode_list

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"

	"github.com/TheManticoreProject/KeyCredentialLink/config"
)

// Run lists all KeyCredentialLinks for a given user.
//
// Parameters:
// - distinguishedName: The distinguished name of the user.
// - config: The configuration of the application.
func Run(distinguishedName string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'list'")
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
		if config.Debug {
			if config.Network.LDAP.UseLdaps {
				logger.Debug(fmt.Sprintf("Connected as '%s\\%s' on ldaps://%s:%d", config.Network.Domain, config.Credentials.Username, config.Network.DomainController, config.Network.LDAP.LDAPPort))
			} else {
				logger.Debug(fmt.Sprintf("Connected as '%s\\%s' on ldap://%s:%d", config.Network.Domain, config.Credentials.Username, config.Network.DomainController, config.Network.LDAP.LDAPPort))
			}

			// If a distinguishedName is provided, we target a specific object.
			query := "(msDS-KeyCredentialLink=*)"
			if len(distinguishedName) > 0 {
				query = fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
			} else {
				query = "(msDS-KeyCredentialLink=*)"
			}

			// We always query the distinguishedName and msDS-KeyCredentialLink attributes.
			attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
			ldapResults, err := ldapSession.QueryWholeSubtree("", query, attributes)
			if err != nil {
				return fmt.Errorf("error querying LDAP server: %s", err)
			}

			// If a distinguishedName is provided, we check if the object exists.
			if len(distinguishedName) > 0 {
				if len(ldapResults) == 0 {
					logger.Warn(fmt.Sprintf("No objects with distinguishedName '%s' found.", distinguishedName))
					return fmt.Errorf("no objects with distinguishedName '%s' found", distinguishedName)
				}
			}

			// We list the msDS-KeyCredentialLink values for the object.
			for _, entry := range ldapResults {
				logger.Info(fmt.Sprintf(" | %s", entry.GetAttributeValue("distinguishedName")))

				msDSKeyCredentialLinkValues := ldapResults[0].GetAttributeValues("msDS-KeyCredentialLink")
				for k, msdskcl := range msDSKeyCredentialLinkValues {
					logger.Info(fmt.Sprintf(" |  | (%d/%d): %s", k+1, len(msDSKeyCredentialLinkValues), msdskcl))
				}
			}
		}
	} else {
		return fmt.Errorf("error connecting to LDAP server")
	}

	return nil
}

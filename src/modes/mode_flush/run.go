package mode_flush

import (
	"fmt"

	"shadowcredentials/core/config"
	"shadowcredentials/ldap"
	"shadowcredentials/logger"
)

// Run flushes the msDS-KeyCredentialLink attribute of a given user.
//
// Parameters:
// - distinguishedName: The distinguished name of the user.
// - config: The configuration of the application.
func Run(distinguishedName string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'flush'")
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

		query := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
		if config.Debug {
			logger.Debug(fmt.Sprintf("Querying ldap: %s", query))
		}

		attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
		ldapResults := ldap.QueryWholeSubtree(&ldapSession, "", query, attributes)

		logger.Info(fmt.Sprintf("Found %d objects with distinguishedName: %s", len(ldapResults), distinguishedName))

		if config.Debug {
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

		err := ldapSession.FlushAttribute(
			ldapResults[0].GetAttributeValue("distinguishedName"),
			"msDS-KeyCredentialLink",
		)

		if err != nil {
			return fmt.Errorf("error adding value to attribute: %s", err)
		} else {
			logger.Info(fmt.Sprintf("Successfully flushed the msDS-KeyCredentialLink attribute of '%s'", distinguishedName))
		}
	} else {
		return fmt.Errorf("error connecting to LDAP server")
	}

	return nil
}

package mode_flush

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"

	"github.com/TheManticoreProject/KeyCredentialLink/config"
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
		}

		query := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
		if config.Debug {
			logger.Debug(fmt.Sprintf("Querying ldap: %s", query))
		}

		attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
		ldapResults, err := ldapSession.QueryWholeSubtree("", query, attributes)
		if err != nil {
			return fmt.Errorf("error querying LDAP server: %s", err)
		}

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

		if config.Debug {
			oldValues := ldapResults[0].GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink")
			if len(oldValues) == 0 {
				logger.Debug("msDS-KeyCredentialLink currently has no values")
			} else {
				logger.Debug(fmt.Sprintf("Existing msDS-KeyCredentialLink values (%d):", len(oldValues)))
				for idx, v := range oldValues {
					logger.Debug(fmt.Sprintf(" | [%d] %s", idx, v))
				}
			}
		}

		err = ldapSession.FlushAttributeValues(
			ldapResults[0].GetAttributeValue("distinguishedName"),
			"msDS-KeyCredentialLink",
		)
		if err != nil {
			return fmt.Errorf("error flushing attribute values: %s", err)
		} else {
			logger.Info(fmt.Sprintf("Successfully flushed the msDS-KeyCredentialLink attribute of '%s'", distinguishedName))
		}
	} else {
		return fmt.Errorf("error connecting to LDAP server")
	}

	return nil
}

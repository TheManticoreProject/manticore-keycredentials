package mode_add

import (
	"fmt"
	"slices"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"

	"github.com/TheManticoreProject/KeyCredentialLink/config"
)

// Run adds a KeyCredentialLink from a user.
//
// Parameters:
// - distinguishedName: The distinguished name of the user.
// - valueToAdd: The value to add from the msDS-KeyCredentialLink attribute.
// - config: The configuration of the application.
//
// Returns:
// - An error if the operation fails.
// - nil if the operation succeeds.
func Run(distinguishedName string, valueToAdd string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'add'")
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
			if config.Debug {
				for _, entry := range ldapResults {
					logger.Debug(fmt.Sprintf(" | %s", entry.GetAttributeValue("distinguishedName")))
				}
			}
			return fmt.Errorf("more than one object with distinguishedName '%s' found (%d)", distinguishedName, len(ldapResults))
		}

		msDSKeyCredentialLinkValues := ldapResults[0].GetAttributeValues("msDS-KeyCredentialLink")
		logger.Info(fmt.Sprintf("Found %d msDS-KeyCredentialLink values for '%s'", len(msDSKeyCredentialLinkValues), distinguishedName))
		if config.Debug {
			for k, msdskcl := range msDSKeyCredentialLinkValues {
				logger.Debug(fmt.Sprintf("(%d/%d): %s", k+1, len(msDSKeyCredentialLinkValues), msdskcl))
			}
		}

		newMSDSKeyCredentialLinkValues := []string{valueToAdd}
		for _, msdskcl := range msDSKeyCredentialLinkValues {
			if !slices.Contains(newMSDSKeyCredentialLinkValues, msdskcl) {
				newMSDSKeyCredentialLinkValues = append(newMSDSKeyCredentialLinkValues, msdskcl)
			} else {
				if config.Debug {
					logger.Debug(fmt.Sprintf("Value '%s' already exists in msDS-KeyCredentialLink", msdskcl))
				}
			}
		}

		if config.Debug {
			logger.Info(fmt.Sprintf("New msDS-KeyCredentialLink values: %d", len(newMSDSKeyCredentialLinkValues)))
			for k, msdskcl := range newMSDSKeyCredentialLinkValues {
				logger.Debug(fmt.Sprintf("(%d/%d): %s", k+1, len(newMSDSKeyCredentialLinkValues), msdskcl))
			}
		}

		err = ldapSession.OverwriteAttributeValues(
			distinguishedName,
			"msDS-KeyCredentialLink",
			newMSDSKeyCredentialLinkValues,
		)
		if err != nil {
			return fmt.Errorf("error replacing attribute values: %s", err)
		}

	}

	return nil
}

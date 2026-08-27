package mode_flush

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
	"github.com/TheManticoreProject/manticore-keycredentials/config"
	"github.com/TheManticoreProject/manticore-keycredentials/utils"
)

// Run flushes the msDS-KeyCredentialLink attribute of a given user.
//
// Parameters:
//
//	distinguishedName (string): The distinguished name of the user.
//	safety (cli.SafetyOptions): The confirmation flag.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(distinguishedName string, safety cli.SafetyOptions, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'flush'")
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

	attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
	entry, err := utils.FindUniqueObject(ldapSession, distinguishedName, attributes, config.Debug)
	if err != nil {
		return err
	}

	dn := entry.GetAttributeValue("distinguishedName")
	oldValues := entry.GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink")

	if config.Debug {
		if len(oldValues) == 0 {
			logger.Debug("msDS-KeyCredentialLink currently has no values")
		} else {
			logger.Debug(fmt.Sprintf("Existing msDS-KeyCredentialLink values (%d):", len(oldValues)))
			for idx, v := range oldValues {
				logger.Debug(fmt.Sprintf(" | [%d] %s", idx, v))
			}
		}
	}

	logger.Print(fmt.Sprintf("[>] Flushing all key credentials from (\x1b[93m1\x1b[0m):\n  └── \x1b[94m%s\x1b[0m", dn))
	logger.Print("")

	if !cli.ConfirmWrite("flush all key credentials from", 2, safety) {
		return nil
	}

	err = ldapSession.FlushAttributeValues(
		dn,
		"msDS-KeyCredentialLink",
	)
	if err != nil {
		return fmt.Errorf("error flushing attribute values: %s", err)
	}

	logger.Info(fmt.Sprintf("Successfully flushed the msDS-KeyCredentialLink attribute of '%s'", distinguishedName))

	return nil
}

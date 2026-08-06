package mode_list

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ldapv3 "github.com/go-ldap/ldap/v3"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
	"github.com/TheManticoreProject/manticore-keycredentials/config"
	"github.com/TheManticoreProject/manticore-keycredentials/utils"
)

// Run lists the raw msDS-KeyCredentialLink values of one or more target objects.
//
// With no target selector it falls back to every object holding a
// msDS-KeyCredentialLink, which is the common "show me the whole domain" case.
//
// Parameters:
//
//	targets (cli.TargetOptions): The target selection flags.
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(targets cli.TargetOptions, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'list'")
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

	var ldapResults []*ldapv3.Entry
	if targets.Empty() {
		// No selector: every object that holds the attribute.
		ldapResults, err = ldapSession.QueryWholeSubtree("", "(msDS-KeyCredentialLink=*)", attributes)
		if err != nil {
			return fmt.Errorf("error querying LDAP server: %s", err)
		}
	} else {
		ldapResults, err = cli.ResolveTargets(ldapSession, targets, attributes, config.Debug)
		if err != nil {
			return err
		}
	}

	// A selector such as -D or --filter resolves objects regardless of whether they
	// hold the attribute, so objects with no value are dropped here to keep the
	// header and count honest: only objects that actually have a key credential are
	// listed. (The whole-domain query already filters on the attribute.)
	withValues := ldapResults[:0]
	for _, entry := range ldapResults {
		if len(entry.GetAttributeValues("msDS-KeyCredentialLink")) > 0 {
			withValues = append(withValues, entry)
		}
	}
	ldapResults = withValues

	if len(ldapResults) == 0 {
		logger.Print("[>] Objects with a msDS-KeyCredentialLink (0)")
		return nil
	}

	logger.Print(fmt.Sprintf("[>] Objects with a msDS-KeyCredentialLink (\x1b[93m%d\x1b[0m):", len(ldapResults)))
	for i, entry := range ldapResults {
		lastEntry := i == len(ldapResults)-1

		if lastEntry {
			logger.Print(fmt.Sprintf("  └── \x1b[94m%s\x1b[0m", entry.GetAttributeValue("distinguishedName")))
		} else {
			logger.Print(fmt.Sprintf("  ├── \x1b[94m%s\x1b[0m", entry.GetAttributeValue("distinguishedName")))
		}

		// Values of an object are nested under it, so the branch of the parent
		// object has to be carried down while it still has siblings below.
		indent := "  │   "
		if lastEntry {
			indent = "      "
		}

		msDSKeyCredentialLinkValues := entry.GetAttributeValues("msDS-KeyCredentialLink")
		for k, msdskcl := range msDSKeyCredentialLinkValues {
			if k < len(msDSKeyCredentialLinkValues)-1 {
				logger.Print(fmt.Sprintf("%s├── \x1b[94m%s\x1b[0m", indent, msdskcl))
			} else {
				logger.Print(fmt.Sprintf("%s└── \x1b[94m%s\x1b[0m", indent, msdskcl))
			}
		}
	}
	logger.Print("")

	return nil
}

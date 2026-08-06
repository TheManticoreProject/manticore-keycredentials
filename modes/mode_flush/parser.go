package mode_flush

import (
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authAesKey *string, authNoPass *bool, ticketCCache *string, ticketKirbi *string) {
	subparser_flush := ap.AddSubParser("flush", "Flush the msDS-KeyCredentialLink attribute of a target object.")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_flush, debug)
	subparser_flush.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the target account.")
	// Shared groups
	cli.RegisterLDAPConnectionSettingsGroup(subparser_flush, domainController, dcHost, ldapPort, useLdaps, useKerberos, dnsNameServer)
	cli.RegisterAuthenticationGroup(subparser_flush, authDomain, authUsername, authNoPass)
	cli.RegisterSecretGroup(subparser_flush, authPassword, authHashes, authAesKey, ticketCCache, ticketKirbi)
}

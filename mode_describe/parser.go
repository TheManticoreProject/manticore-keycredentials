package mode_describe

import (
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authAesKey *string, authNoPass *bool, ticketCCache *string, ticketKirbi *string) {
	subparser_describe := ap.AddSubParser("describe", "Display information about the KeyCredentialLink values of a target object.")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_describe, debug)
	subparser_describe.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the target account.")
	// Shared groups
	cli.RegisterLDAPConnectionSettingsGroup(subparser_describe, domainController, dcHost, ldapPort, useLdaps, useKerberos, dnsNameServer)
	cli.RegisterAuthenticationGroup(subparser_describe, authDomain, authUsername)
	cli.RegisterSecretGroup(subparser_describe, authNoPass, authPassword, authHashes, authAesKey, ticketCCache, ticketKirbi)
}

package mode_list

import (
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, targets *cli.TargetOptions, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authAesKey *string, authNoPass *bool, ticketCCache *string, ticketKirbi *string) {
	subparser_list := ap.AddSubParser("list", "List the raw msDS-KeyCredentialLink values of one or more target objects.")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_list, debug)
	// Targets. When none is given, list falls back to every object holding the attribute.
	cli.RegisterTargetGroup(subparser_list, targets)
	// Shared groups
	cli.RegisterLDAPConnectionSettingsGroup(subparser_list, domainController, dcHost, ldapPort, useLdaps, useKerberos, dnsNameServer)
	cli.RegisterAuthenticationGroup(subparser_list, authDomain, authUsername, authNoPass)
	cli.RegisterSecretGroup(subparser_list, authPassword, authHashes, authAesKey, ticketCCache, ticketKirbi)
}

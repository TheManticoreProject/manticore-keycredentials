package mode_find

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, pfxCertificate *string, pfxPassword *string, pemFile *string, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authAesKey *string, authNoPass *bool, ticketCCache *string, ticketKirbi *string) {
	subparser_find := ap.AddSubParser("find", "Find the objects configured with a given certificate or public key.")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_find, debug)

	subparser_find.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", false, "Distinguished name of a single object to check. If omitted, every object holding a msDS-KeyCredentialLink is searched.")
	subparser_find.NewStringArgument(pfxPassword, "", "--pfx-password", "", false, "Password of the PFX file.")

	// Key to search for
	subparser_find_group_key, err := subparser_find.NewRequiredMutuallyExclusiveArgumentGroup("Key to search for")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_find_group_key.NewStringArgument(pfxCertificate, "", "--pfx", "", false, "PFX file holding the certificate to search for.")
		subparser_find_group_key.NewStringArgument(pemFile, "", "--pem", "", false, "PEM file holding the certificate, private key or public key to search for.")
	}

	// Shared groups
	cli.RegisterLDAPConnectionSettingsGroup(subparser_find, domainController, dcHost, ldapPort, useLdaps, useKerberos, dnsNameServer)
	cli.RegisterAuthenticationGroup(subparser_find, authDomain, authUsername, authNoPass)
	cli.RegisterSecretGroup(subparser_find, authPassword, authHashes, authAesKey, ticketCCache, ticketKirbi)
}

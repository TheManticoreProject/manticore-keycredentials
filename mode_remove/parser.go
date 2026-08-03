package mode_remove

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, targets *cli.TargetOptions, safety *cli.SafetyOptions, pfxCertificate *string, pfxPassword *string, pemFile *string, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authAesKey *string, authNoPass *bool, ticketCCache *string, ticketKirbi *string) {
	subparser_remove := ap.AddSubParser("remove", "Remove a single specified certificate from one or more target objects.")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_remove, debug)
	subparser_remove.NewStringArgument(pfxPassword, "", "--pfx-password", "", false, "Password of the PFX file.")

	// Certificate to remove
	subparser_remove_group_source, err := subparser_remove.NewRequiredMutuallyExclusiveArgumentGroup("Certificate to remove")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_remove_group_source.NewStringArgument(pfxCertificate, "", "--pfx", "", false, "PFX file holding the certificate to remove.")
		subparser_remove_group_source.NewStringArgument(pemFile, "", "--pem", "", false, "PEM file holding the certificate, private key or public key to remove.")
	}

	// Targets and safety
	cli.RegisterTargetGroup(subparser_remove, targets)
	cli.RegisterSafetyGroup(subparser_remove, safety)
	// Shared groups
	cli.RegisterLDAPConnectionSettingsGroup(subparser_remove, domainController, dcHost, ldapPort, useLdaps, useKerberos, dnsNameServer)
	cli.RegisterAuthenticationGroup(subparser_remove, authDomain, authUsername)
	cli.RegisterSecretGroup(subparser_remove, authNoPass, authPassword, authHashes, authAesKey, ticketCCache, ticketKirbi)
}

package mode_extract

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, outputDir *string, exportPem *bool, exportDer *bool, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authAesKey *string, authNoPass *bool, ticketCCache *string, ticketKirbi *string) {
	subparser_extract := ap.AddSubParser("extract", "Extract the public key of a certificate set on a target object.")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_extract, debug)
	subparser_extract.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the target account.")
	subparser_extract.NewStringArgument(outputDir, "-o", "--output-dir", "./keys/", false, "Directory the extracted public keys are written to.")

	// Export format. Neither being set defaults to PEM in the runner.
	subparser_extract_group_export, err := subparser_extract.NewNotRequiredMutuallyExclusiveArgumentGroup("Export format")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_extract_group_export.NewBoolArgument(exportPem, "", "--export-pem", false, "Export the public key in PEM format (default).")
		subparser_extract_group_export.NewBoolArgument(exportDer, "", "--export-der", false, "Export the public key in DER format.")
	}

	// Shared groups
	cli.RegisterLDAPConnectionSettingsGroup(subparser_extract, domainController, dcHost, ldapPort, useLdaps, useKerberos, dnsNameServer)
	cli.RegisterAuthenticationGroup(subparser_extract, authDomain, authUsername, authNoPass)
	cli.RegisterSecretGroup(subparser_extract, authPassword, authHashes, authAesKey, ticketCCache, ticketKirbi)
}

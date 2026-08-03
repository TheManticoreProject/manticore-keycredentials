package mode_enroll

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, targets *cli.TargetOptions, safety *cli.SafetyOptions, identifier *string, creationTime *string, lastLogonTime *string, notBeforeTime *string, notAfterTime *string, deviceId *string, keySize *int, exportPem *bool, exportPfx *bool, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authAesKey *string, authNoPass *bool, ticketCCache *string, ticketKirbi *string) {
	subparser_enroll := ap.AddSubParser("enroll", "Create and attach a new certificate to one or more target objects.")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_enroll, debug)

	// KeyCredential
	subparser_enroll_group_keycredential, err := subparser_enroll.NewArgumentGroup("KeyCredential")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_enroll_group_keycredential.NewStringArgument(identifier, "", "--identifier", "", false, "Identifier of the KeyCredential. A fresh one is generated per object when omitted.")
		subparser_enroll_group_keycredential.NewStringArgument(creationTime, "", "--creation-time", "", false, "Creation time of the KeyCredential.")
		subparser_enroll_group_keycredential.NewStringArgument(lastLogonTime, "", "--last-logon-time", "", false, "Last logon time of the KeyCredential.")
		subparser_enroll_group_keycredential.NewStringArgument(notBeforeTime, "", "--not-before-time", "", false, "Not before time of the certificate.")
		subparser_enroll_group_keycredential.NewStringArgument(notAfterTime, "", "--not-after-time", "", false, "Not after time of the certificate.")
		subparser_enroll_group_keycredential.NewIntArgument(keySize, "", "--key-size", 2048, false, "Key size of the certificate.")
		subparser_enroll_group_keycredential.NewStringArgument(deviceId, "", "--device-id", "", false, "Device ID of the KeyCredential. A fresh one is generated per object when omitted.")
	}
	// Export certificate
	subparser_enroll_group_export, err := subparser_enroll.NewRequiredMutuallyExclusiveArgumentGroup("Export certificate")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_enroll_group_export.NewBoolArgument(exportPem, "", "--export-pem", false, "Export the certificate in PEM format.")
		subparser_enroll_group_export.NewBoolArgument(exportPfx, "", "--export-pfx", false, "Export the certificate in PFX format.")
	}

	// Targets and safety
	cli.RegisterTargetGroup(subparser_enroll, targets)
	cli.RegisterSafetyGroup(subparser_enroll, safety)
	// Shared groups
	cli.RegisterLDAPConnectionSettingsGroup(subparser_enroll, domainController, dcHost, ldapPort, useLdaps, useKerberos, dnsNameServer)
	cli.RegisterAuthenticationGroup(subparser_enroll, authDomain, authUsername)
	cli.RegisterSecretGroup(subparser_enroll, authNoPass, authPassword, authHashes, authAesKey, ticketCCache, ticketKirbi)
}

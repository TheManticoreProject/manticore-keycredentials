package mode_attach

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, targets *cli.TargetOptions, safety *cli.SafetyOptions, pfxCertificate *string, pfxPassword *string, pemFile *string, identifier *string, creationTime *string, lastLogonTime *string, deviceId *string, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authAesKey *string, authNoPass *bool, ticketCCache *string, ticketKirbi *string) {
	subparser_attach := ap.AddSubParser("attach", "Attach an existing certificate to one or more target objects.")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_attach, debug)
	subparser_attach.NewStringArgument(pfxPassword, "", "--pfx-password", "", false, "Password of the PFX file.")

	// Certificate source
	subparser_attach_group_source, err := subparser_attach.NewRequiredMutuallyExclusiveArgumentGroup("Certificate source")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_attach_group_source.NewStringArgument(pfxCertificate, "", "--pfx", "", false, "PFX file holding the certificate to attach.")
		subparser_attach_group_source.NewStringArgument(pemFile, "", "--pem", "", false, "PEM file holding the certificate, private key or public key to attach.")
	}

	// KeyCredential
	subparser_attach_group_keycredential, err := subparser_attach.NewArgumentGroup("KeyCredential")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_attach_group_keycredential.NewStringArgument(identifier, "", "--identifier", "", false, "Identifier of the KeyCredential. A fresh one is generated per object when omitted.")
		subparser_attach_group_keycredential.NewStringArgument(creationTime, "", "--creation-time", "", false, "Creation time of the KeyCredential.")
		subparser_attach_group_keycredential.NewStringArgument(lastLogonTime, "", "--last-logon-time", "", false, "Last logon time of the KeyCredential.")
		subparser_attach_group_keycredential.NewStringArgument(deviceId, "", "--device-id", "", false, "Device ID of the KeyCredential. A fresh one is generated per object when omitted.")
	}

	// Targets and safety
	cli.RegisterTargetGroup(subparser_attach, targets)
	cli.RegisterSafetyGroup(subparser_attach, safety)
	// Shared groups
	cli.RegisterLDAPConnectionSettingsGroup(subparser_attach, domainController, dcHost, ldapPort, useLdaps, useKerberos, dnsNameServer)
	cli.RegisterAuthenticationGroup(subparser_attach, authDomain, authUsername, authNoPass)
	cli.RegisterSecretGroup(subparser_attach, authPassword, authHashes, authAesKey, ticketCCache, ticketKirbi)
}

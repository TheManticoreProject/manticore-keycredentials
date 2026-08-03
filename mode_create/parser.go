package mode_create

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, subject *string, notBeforeTime *string, notAfterTime *string, keySize *int, outputDir *string, pfxPassword *string) {
	subparser_create := ap.AddSubParser("create", "Create a new certificate and save it locally (private key and certificate).")
	// Configuration
	cli.RegisterConfigurationGroup(subparser_create, debug)

	subparser_create.NewStringArgument(subject, "-s", "--subject", "manticore-keycredentials", false, "Common name (CN) of the generated certificate.")
	subparser_create.NewStringArgument(outputDir, "-o", "--output-dir", "./keys/", false, "Directory the certificate, private key and PFX are written to.")
	subparser_create.NewStringArgument(pfxPassword, "", "--pfx-password", "", false, "Password of the generated PFX. A random one is used when omitted.")

	// Certificate
	subparser_create_group_certificate, err := subparser_create.NewArgumentGroup("Certificate")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		subparser_create_group_certificate.NewIntArgument(keySize, "", "--key-size", 2048, false, "Key size of the certificate.")
		subparser_create_group_certificate.NewStringArgument(notBeforeTime, "", "--not-before-time", "", false, "Not before time of the certificate.")
		subparser_create_group_certificate.NewStringArgument(notAfterTime, "", "--not-after-time", "", false, "Not after time of the certificate.")
	}
}

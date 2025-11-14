package mode_attach

import (
	"fmt"

	"github.com/TheManticoreProject/goopts/parser"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, pfxPassword *string, privateKey *string, publicKey *string, pfxCertificate *string) {
	subparser_attach := ap.AddSubParser("attach", "Attach an existing certificate to a specified object.")

	// Configuration flags
	subparser_attach.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")
	subparser_attach.NewStringArgument(distinguishedName, "", "--distinguished-name", "", true, "Distinguished name of the target account.")

	subparser_attach.NewStringArgument(pfxPassword, "", "--pfx-password", "", false, "Password for the PFX certificate.")

	// KeyCredential source
	subparser_attach_group_keycredential, err := subparser_attach.NewRequiredMutuallyExclusiveArgumentGroup("KeyCredential source")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_attach_group_keycredential.NewStringArgument(privateKey, "", "--private-key", "", false, "Private key for the KeyCredential.")
		subparser_attach_group_keycredential.NewStringArgument(publicKey, "", "--public-key", "", false, "Public key for the KeyCredential.")
		subparser_attach_group_keycredential.NewStringArgument(pfxCertificate, "", "--pfx-certificate", "", false, "PFX certificate for the KeyCredential.")
	}

}

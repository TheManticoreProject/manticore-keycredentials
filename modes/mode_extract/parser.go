package mode_extract

import (
	"fmt"

	"github.com/TheManticoreProject/goopts/parser"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, exportPem *bool, exportPfx *bool) {
	subparser_extract := ap.AddSubParser("extract", "Extract a KeyCredentialLink from an object.")

	// Configuration flags
	subparser_extract.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")
	subparser_extract.NewStringArgument(distinguishedName, "-D", "--distinguished-name", "", true, "Distinguished name of the target account.")

	// Export certificate
	subparser_extract_group_export, err := subparser_extract.NewRequiredMutuallyExclusiveArgumentGroup("Export certificate")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_extract_group_export.NewBoolArgument(exportPem, "", "--export-pem", false, "Export the certificate in PEM format.")
		subparser_extract_group_export.NewBoolArgument(exportPfx, "", "--export-pfx", false, "Export the certificate in PFX format.")
	}
}

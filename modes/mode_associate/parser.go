package mode_associate

import (
	"github.com/TheManticoreProject/goopts/parser"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string) {
	subparser_associate := ap.AddSubParser("associate", "Add a new or existing KeyCredentialLink to one or more objects.")

	// Configuration flags
	subparser_associate.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")
	subparser_associate.NewStringArgument(distinguishedName, "", "--distinguished-name", "", true, "Distinguished name of the target account.")
}

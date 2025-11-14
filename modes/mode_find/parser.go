package mode_find

import (
	"github.com/TheManticoreProject/goopts/parser"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string) {
	subparser_find := ap.AddSubParser("find", "Find a KeyCredentialLink in an object.")

	// Configuration flags
	subparser_find.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

}

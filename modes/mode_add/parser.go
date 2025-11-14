package mode_add

import (
	"fmt"

	"github.com/TheManticoreProject/goopts/parser"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, valueToAdd *string, useLdaps *bool, ldapPort *int, domainController *string, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authNoPass *bool) {
	subparser_add := ap.AddSubParser("add", "Add a KeyCredentialLink value to a specified object.")
	// Configuration flags
	subparser_add.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")
	subparser_add.NewStringArgument(distinguishedName, "", "--distinguished-name", "", false, "Distinguished name of the target account.")
	subparser_add.NewStringArgument(valueToAdd, "", "--value-to-add", "", true, "Value to add to the msDS-KeyCredentialLink attribute.")
	// Network settings
	subparser_add_group_network, err := subparser_add.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_add_group_network.NewBoolArgument(useLdaps, "", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_add_group_network.NewIntArgument(ldapPort, "", "--ldap-port", 389, false, "LDAP port to use.")
		subparser_add_group_network.NewStringArgument(domainController, "", "--dc-ip", "", false, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_add_group_network.NewStringArgument(dnsNameServer, "", "--dns-name-server", "", false, "DNS name server to use.")
	}
	// Authentication
	subparser_add_group_auth, err := subparser_add.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_add_group_auth.NewStringArgument(authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		subparser_add_group_auth.NewStringArgument(authUsername, "-u", "--user", "", false, "User to authenticate with.")
	}
	// Secret
	subparser_add_group_secret, err := subparser_add.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_add_group_secret.NewBoolArgument(authNoPass, "", "--no-pass", false, "Don't ask for password (useful for -k).")
		subparser_add_group_secret.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_add_group_secret.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		subparser_add_group_secret.NewStringArgument(authHashes, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	}
}

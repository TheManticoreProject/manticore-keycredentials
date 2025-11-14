package mode_remove

import (
	"fmt"

	"github.com/TheManticoreProject/goopts/parser"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, valueToRemove *string, useLdaps *bool, ldapPort *int, domainController *string, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authNoPass *bool) {
	subparser_remove := ap.AddSubParser("remove", "Remove a KeyCredentialLink from a specified object.")
	// Configuration flags
	subparser_remove.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")
	subparser_remove.NewStringArgument(distinguishedName, "", "--distinguished-name", "", false, "Distinguished name of the target account.")
	subparser_remove.NewStringArgument(valueToRemove, "", "--value-to-remove", "", true, "Value to remove from the msDS-KeyCredentialLink attribute.")
	// Network settings
	subparser_remove_group_network, err := subparser_remove.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_remove_group_network.NewBoolArgument(useLdaps, "", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_remove_group_network.NewIntArgument(ldapPort, "", "--ldap-port", 389, false, "LDAP port to use.")
		subparser_remove_group_network.NewStringArgument(domainController, "", "--dc-ip", "", false, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_remove_group_network.NewStringArgument(dnsNameServer, "", "--dns-name-server", "", false, "DNS name server to use.")
	}
	// Authentication
	subparser_remove_group_auth, err := subparser_remove.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_remove_group_auth.NewStringArgument(authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		subparser_remove_group_auth.NewStringArgument(authUsername, "-u", "--user", "", false, "User to authenticate with.")
	}
	// Secret
	subparser_remove_group_secret, err := subparser_remove.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_remove_group_secret.NewBoolArgument(authNoPass, "", "--no-pass", false, "Don't ask for password (useful for -k).")
		subparser_remove_group_secret.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_remove_group_secret.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		subparser_remove_group_secret.NewStringArgument(authHashes, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	}
}

package mode_flush

import (
	"fmt"

	"github.com/TheManticoreProject/goopts/parser"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, useLdaps *bool, ldapPort *int, domainController *string, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authNoPass *bool) {
	subparser_flush := ap.AddSubParser("flush", "Flush the msDS-KeyCredentialLink attribute of an object.")
	// Configuration flags
	subparser_flush.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")
	subparser_flush.NewStringArgument(distinguishedName, "", "--distinguished-name", "", false, "Distinguished name of the target account.")
	// Network settings
	subparser_flush_group_network, err := subparser_flush.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_flush_group_network.NewBoolArgument(useLdaps, "", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_flush_group_network.NewIntArgument(ldapPort, "", "--ldap-port", 389, false, "LDAP port to use.")
		subparser_flush_group_network.NewStringArgument(domainController, "", "--dc-ip", "", false, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_flush_group_network.NewStringArgument(dnsNameServer, "", "--dns-name-server", "", false, "DNS name server to use.")
	}
	// Authentication
	subparser_flush_group_auth, err := subparser_flush.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_flush_group_auth.NewStringArgument(authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		subparser_flush_group_auth.NewStringArgument(authUsername, "-u", "--user", "", false, "User to authenticate with.")
	}
	// Secret
	subparser_flush_group_secret, err := subparser_flush.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_flush_group_secret.NewBoolArgument(authNoPass, "", "--no-pass", false, "Don't ask for password (useful for -k).")
		subparser_flush_group_secret.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_flush_group_secret.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		subparser_flush_group_secret.NewStringArgument(authHashes, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	}
}

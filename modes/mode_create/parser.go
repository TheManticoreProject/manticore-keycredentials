package mode_create

import (
	"fmt"

	"github.com/TheManticoreProject/goopts/parser"
)

func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, distinguishedName *string, identifier *string, creationTime *string, lastLogonTime *string, notBeforeTime *string, notAfterTime *string, deviceId *string, keySize *int, exportPem *bool, exportPfx *bool, useLdaps *bool, ldapPort *int, domainController *string, dnsNameServer *string, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authNoPass *bool) {
	subparser_create := ap.AddSubParser("create", "Create a new KeyCredentialLink and attach it to a specified object.")
	// Configuration flags
	subparser_create.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	subparser_create.NewStringArgument(distinguishedName, "", "--distinguished-name", "", true, "Distinguished name of the target account.")
	// Network settings
	subparser_create_group_network, err := subparser_create.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_network.NewBoolArgument(useLdaps, "", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_create_group_network.NewIntArgument(ldapPort, "", "--ldap-port", 389, false, "LDAP port to use.")
		subparser_create_group_network.NewStringArgument(domainController, "", "--dc-ip", "", false, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_create_group_network.NewStringArgument(dnsNameServer, "", "--dns-name-server", "", false, "DNS name server to use.")
	}
	// KeyCredential
	subparser_create_group_keycredential, err := subparser_create.NewArgumentGroup("KeyCredential")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_keycredential.NewStringArgument(identifier, "", "--identifier", "", false, "Identifier of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(creationTime, "", "--creation-time", "", false, "Creation time of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(lastLogonTime, "", "--last-logon-time", "", false, "Last logon time of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(notBeforeTime, "", "--not-before-time", "", false, "Not before time of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(notAfterTime, "", "--not-after-time", "", false, "Not after time of the KeyCredential.")
		subparser_create_group_keycredential.NewIntArgument(keySize, "", "--key-size", 2048, false, "Key size of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(deviceId, "", "--device-id", "", false, "Device ID of the KeyCredential.")
	}
	// Export certificate
	subparser_create_group_export, err := subparser_create.NewRequiredMutuallyExclusiveArgumentGroup("Export certificate")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_export.NewBoolArgument(exportPem, "", "--export-pem", false, "Export the certificate in PEM format.")
		subparser_create_group_export.NewBoolArgument(exportPfx, "", "--export-pfx", false, "Export the certificate in PFX format.")
	}
	// Authentication
	subparser_create_group_auth, err := subparser_create.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_auth.NewStringArgument(authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		subparser_create_group_auth.NewStringArgument(authUsername, "-u", "--user", "", false, "User to authenticate with.")
	}
	// Secret
	subparser_create_group_secret, err := subparser_create.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_secret.NewBoolArgument(authNoPass, "", "--no-pass", false, "Don't ask for password (useful for -k).")
		subparser_create_group_secret.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_create_group_secret.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		subparser_create_group_secret.NewStringArgument(authHashes, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	}
}

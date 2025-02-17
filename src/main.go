package main

import (
	"goWhisker/core/config"
	"goWhisker/logger"
	"goWhisker/modes/mode_attach"
	"goWhisker/modes/mode_create"
	"goWhisker/modes/mode_export"
	"goWhisker/modes/mode_flush"
	"goWhisker/modes/mode_info"
	"goWhisker/modes/mode_list"
	"goWhisker/modes/mode_remove"
	"goWhisker/modes/mode_spray"

	"github.com/p0dalirius/goopts/subparser"

	"fmt"
)

var (
	mode string

	// Configuration
	useLdaps bool
	debug    bool

	// KeyCredential
	distinguishedName string
	owner             string
	identifier        string
	creationTime      string
	lastLogonTime     string
	notBeforeTime     string
	notAfterTime      string
	deviceId          string
	keySize           int

	// Network settings
	domainController string
	ldapPort         int
	dnsNameServer    string

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	asp := subparser.ArgumentsSubparser{
		Banner:          "goWhisker v1.0 - by Remi GASCOU (Podalirius)",
		Name:            "mode",
		Value:           &mode,
		CaseInsensitive: true,
	}

	// attach ==================================================================================================================
	subparser_attach := asp.AddSubParser("attach", "Attach an existing certificate to a specified object.")
	subparser_attach.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// create ==========================================================================================================================
	subparser_create := asp.AddSubParser("create", "Create a new KeyCredentialLink and attach it to a specified object.")
	// Configuration flags
	subparser_create.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	// Network settings
	subparser_create_group_network, err := subparser_create.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_network.NewBoolArgument(&useLdaps, "", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_create_group_network.NewIntArgument(&ldapPort, "", "--ldap-port", 389, false, "LDAP port to use.")
		subparser_create_group_network.NewStringArgument(&domainController, "", "--dc-ip", "", false, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_create_group_network.NewStringArgument(&dnsNameServer, "", "--dns-name-server", "", false, "DNS name server to use.")
	}
	// KeyCredential
	subparser_create_group_keycredential, err := subparser_create.NewArgumentGroup("KeyCredential")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_keycredential.NewStringArgument(&distinguishedName, "", "--distinguished-name", "", false, "Distinguished name of the target account.")
		subparser_create_group_keycredential.NewStringArgument(&identifier, "", "--identifier", "", false, "Identifier of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(&creationTime, "", "--creation-time", "", false, "Creation time of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(&lastLogonTime, "", "--last-logon-time", "", false, "Last logon time of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(&notBeforeTime, "", "--not-before-time", "", false, "Not before time of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(&notAfterTime, "", "--not-after-time", "", false, "Not after time of the KeyCredential.")
		subparser_create_group_keycredential.NewIntArgument(&keySize, "", "--key-size", 2048, false, "Key size of the KeyCredential.")
		subparser_create_group_keycredential.NewStringArgument(&deviceId, "", "--device-id", "", false, "Device ID of the KeyCredential.")
	}
	// Authentication
	subparser_create_group_auth, err := subparser_create.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		subparser_create_group_auth.NewStringArgument(&authUsername, "-u", "--user", "", false, "User to authenticate with.")
	}
	// Secret
	subparser_create_group_secret, err := subparser_create.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_secret.NewBoolArgument(&authNoPass, "", "--no-pass", false, "Don't ask for password (useful for -k).")
		subparser_create_group_secret.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_create_group_secret.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		subparser_create_group_secret.NewStringArgument(&authHashes, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	}

	// export ==================================================================================================================
	subparser_export := asp.AddSubParser("export", "Export a KeyCredentialLink to a PEM, PFX, or binary format.")
	subparser_export.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// flush ==========================================================================================================================
	subparser_flush := asp.AddSubParser("flush", "Flush the msDS-KeyCredentialLink attribute of an object.")
	// Configuration flags
	subparser_flush.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	subparser_flush.NewStringArgument(&distinguishedName, "", "--distinguished-name", "", false, "Distinguished name of the target account.")
	// Network settings
	subparser_flush_group_network, err := subparser_flush.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_flush_group_network.NewBoolArgument(&useLdaps, "", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_flush_group_network.NewIntArgument(&ldapPort, "", "--ldap-port", 389, false, "LDAP port to use.")
		subparser_flush_group_network.NewStringArgument(&domainController, "", "--dc-ip", "", false, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_flush_group_network.NewStringArgument(&dnsNameServer, "", "--dns-name-server", "", false, "DNS name server to use.")
	}
	// Authentication
	subparser_flush_group_auth, err := subparser_flush.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_flush_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		subparser_flush_group_auth.NewStringArgument(&authUsername, "-u", "--user", "", false, "User to authenticate with.")
	}
	// Secret
	subparser_flush_group_secret, err := subparser_flush.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_flush_group_secret.NewBoolArgument(&authNoPass, "", "--no-pass", false, "Don't ask for password (useful for -k).")
		subparser_flush_group_secret.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_flush_group_secret.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		subparser_flush_group_secret.NewStringArgument(&authHashes, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	}

	// list ==================================================================================================================
	subparser_list := asp.AddSubParser("list", "List KeyCredentialLink values of a specified object.")
	subparser_list.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// remove ==================================================================================================================
	subparser_remove := asp.AddSubParser("remove", "Remove a KeyCredentialLink from one or more objects.")
	subparser_remove.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// spray ==================================================================================================================
	subparser_spray := asp.AddSubParser("spray", "Add a new or existing KeyCredentialLink to one or more objects.")
	subparser_spray.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// subparser_remove ==================================================================================================================

	// subparser_remove := asp.AddSubParser("remove", "Remove a KeyCredentialLink from a user account.")
	// subparser_list := asp.AddSubParser("list", "List KeyCredentialLink for a user account.")
	// subparser_clear := asp.AddSubParser("clear", "Clear all KeyCredentialLink from a user account.")

	// // Target account
	// group_target, err := ap.NewRequiredMutuallyExclusiveArgumentGroup("Target")
	// if err != nil {
	// 	fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	// } else {
	// 	group_target.NewStringArgument(&distinguishedName, "-t", "--target", "", false, "Target account.")
	// 	group_target.NewStringArgument(&rawValue, "-tl", "--target-list", "", false, "Path to a file with target accounts names (one per line).")
	// }

	// // Action
	// ap.NewStringArgument(&rawValue, "-a", "--action", "list", false, "Action to operate on msDS-KeyCredentialLink. Choices: list, add, spray, remove, clear, info, export, import.")

	// // Secret
	// group_secret, err := ap.NewArgumentGroup("Secret")
	// if err != nil {
	// 	fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	// } else {

	// 	group_secret.NewBoolArgument(&useLdaps, "-k", "--kerberos", false, "Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line.")
	// }

	// // Arguments when setting -action to add
	// group_add, err := ap.NewArgumentGroup("Arguments when setting -action to add")
	// if err != nil {
	// 	fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	// } else {
	// 	group_add.NewStringArgument(&authPassword, "-P", "--pfx-password", "", false, "Password for the PFX stored self-signed certificate (will be random if not set, not needed when exporting to PEM).")
	// 	group_add.NewStringArgument(&authPassword, "-f", "--filename", "", false, "Filename to store the generated self-signed PEM or PFX certificate and key, or filename for the 'import'/'export' actions.")
	// 	group_add.NewStringArgument(&authPassword, "-e", "--export", "PFX", false, "Choose to export cert+private key in PEM or PFX (i.e. #PKCS12) (default: PFX).")
	// }

	// // Arguments when setting -action to remove
	// group_remove, err := ap.NewArgumentGroup("Arguments when setting -action to remove")
	// if err != nil {
	// 	fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	// } else {
	// 	group_remove.NewStringArgument(&authPassword, "-D", "--device-id", "", false, "Device ID of the KeyCredentialLink to remove when setting -action to remove.")
	// }

	asp.Parse()

	// if !group_network.LongNameToArgument["--port"].IsPresent() {
	// 	if useLdaps {
	// 		ldapPort = 636
	// 	} else {
	// 		ldapPort = 389
	// 	}
	// }
}

func main() {
	parseArgs()

	config := config.Config{
		Debug: debug,
		Credentials: config.Credentials{
			Username: authUsername,
			Domain:   authDomain,
			Password: authPassword,
		},
		Network: config.Network{
			LDAP: config.LDAP{
				UseLdaps: useLdaps,
				LDAPPort: ldapPort,
			},
			DNSNameServer:    dnsNameServer,
			DomainController: domainController,
			Domain:           authDomain,
		},
	}

	if mode == "attach" {
		mode_attach.Run(distinguishedName, config)
	} else if mode == "create" {
		mode_create.Run(distinguishedName, identifier, creationTime, lastLogonTime, notBeforeTime, notAfterTime, deviceId, keySize, config)
	} else if mode == "export" {
		mode_export.Run(distinguishedName, config)
	} else if mode == "flush" {
		mode_flush.Run(distinguishedName, config)
	} else if mode == "list" {
		mode_list.Run(distinguishedName, config)
	} else if mode == "remove" {
		mode_remove.Run(distinguishedName, config)
	} else if mode == "spray" {
		mode_spray.Run(distinguishedName, config)
	} else if mode == "info" {
		mode_info.Run(distinguishedName, config)
	} else {
		logger.Warn(fmt.Sprintf("Invalid mode: %s", mode))
	}

	logger.Info("All done!")
}

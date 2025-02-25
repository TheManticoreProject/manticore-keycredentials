package main

import (
	"shadowcredentials/core/config"
	"shadowcredentials/logger"
	"shadowcredentials/modes/mode_attach"
	"shadowcredentials/modes/mode_create"
	"shadowcredentials/modes/mode_extract"
	"shadowcredentials/modes/mode_flush"
	"shadowcredentials/modes/mode_info"
	"shadowcredentials/modes/mode_list"
	"shadowcredentials/modes/mode_remove"
	"shadowcredentials/modes/mode_spray"

	"github.com/p0dalirius/goopts/subparser"

	"fmt"
)

var (
	mode string

	distinguishedName string

	// KeyCredential source
	pfxPassword    string
	privateKey     string
	publicKey      string
	pfxCertificate string
	exportPem      bool
	exportPfx      bool

	// KeyCredential build
	identifier    string
	creationTime  string
	lastLogonTime string
	notBeforeTime string
	notAfterTime  string
	deviceId      string
	keySize       int

	// Configuration
	useLdaps bool
	debug    bool

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
		Banner:          "shadowcredentials v1.0 - by Remi GASCOU (Podalirius)",
		Name:            "mode",
		Value:           &mode,
		CaseInsensitive: true,
	}

	// attach ==================================================================================================================
	subparser_attach := asp.AddSubParser("attach", "Attach an existing certificate to a specified object.")
	subparser_attach.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	subparser_attach.NewStringArgument(&distinguishedName, "", "--distinguished-name", "", false, "Distinguished name of the target account.")
	subparser_attach.NewStringArgument(&pfxPassword, "", "--pfx-password", "", false, "Password for the PFX certificate.")
	// KeyCredential source
	subparser_attach_group_keycredential, err := subparser_attach.NewRequiredMutuallyExclusiveArgumentGroup("KeyCredential source")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_attach_group_keycredential.NewStringArgument(&privateKey, "", "--private-key", "", false, "Private key for the KeyCredential.")
		subparser_attach_group_keycredential.NewStringArgument(&publicKey, "", "--public-key", "", false, "Public key for the KeyCredential.")
		subparser_attach_group_keycredential.NewStringArgument(&pfxCertificate, "", "--pfx-certificate", "", false, "PFX certificate for the KeyCredential.")
	}

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
	// Export certificate
	subparser_create_group_export, err := subparser_create.NewRequiredMutuallyExclusiveArgumentGroup("Export certificate")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_create_group_export.NewBoolArgument(&exportPem, "", "--export-pem", false, "Export the certificate in PEM format.")
		subparser_create_group_export.NewBoolArgument(&exportPfx, "", "--export-pfx", false, "Export the certificate in PFX format.")
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

	// extract ==================================================================================================================
	subparser_extract := asp.AddSubParser("extract", "Extract a KeyCredentialLink from an object.")
	subparser_extract.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// find ==================================================================================================================
	subparser_find := asp.AddSubParser("find", "Find objects with a KeyCredentialLink matching a specified value.")
	subparser_find.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

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
	// Configuration flags
	subparser_list.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	subparser_list.NewStringArgument(&distinguishedName, "", "--distinguished-name", "", false, "Distinguished name of the target account.")
	// Network settings
	subparser_list_group_network, err := subparser_list.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_list_group_network.NewBoolArgument(&useLdaps, "", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		subparser_list_group_network.NewIntArgument(&ldapPort, "", "--ldap-port", 389, false, "LDAP port to use.")
		subparser_list_group_network.NewStringArgument(&domainController, "", "--dc-ip", "", false, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		subparser_list_group_network.NewStringArgument(&dnsNameServer, "", "--dns-name-server", "", false, "DNS name server to use.")
	}
	// Authentication
	subparser_list_group_auth, err := subparser_list.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_list_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		subparser_list_group_auth.NewStringArgument(&authUsername, "-u", "--user", "", false, "User to authenticate with.")
	}
	// Secret
	subparser_list_group_secret, err := subparser_list.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_list_group_secret.NewBoolArgument(&authNoPass, "", "--no-pass", false, "Don't ask for password (useful for -k).")
		subparser_list_group_secret.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_list_group_secret.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		subparser_list_group_secret.NewStringArgument(&authHashes, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	}

	// remove ==================================================================================================================
	subparser_remove := asp.AddSubParser("remove", "Remove a KeyCredentialLink from one or more objects.")
	subparser_remove.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// spray ==================================================================================================================
	subparser_spray := asp.AddSubParser("spray", "Add a new or existing KeyCredentialLink to one or more objects.")
	subparser_spray.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// Parse arguments
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
		err := mode_attach.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_attach: %s", err))
		}
	} else if mode == "create" {
		err := mode_create.Run(distinguishedName, identifier, creationTime, lastLogonTime, notBeforeTime, notAfterTime, deviceId, keySize, exportPem, exportPfx, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_create: %s", err))
		}
	} else if mode == "extract" {
		err := mode_extract.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_extract: %s", err))
		}
	} else if mode == "flush" {
		err := mode_flush.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_flush: %s", err))
		}
	} else if mode == "list" {
		err := mode_list.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_list: %s", err))
		}
	} else if mode == "remove" {
		err := mode_remove.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_remove: %s", err))
		}
	} else if mode == "spray" {
		err := mode_spray.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_spray: %s", err))
		}
	} else if mode == "info" {
		err := mode_info.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_info: %s", err))
		}
	} else {
		logger.Warn(fmt.Sprintf("Invalid mode: %s", mode))
	}

	logger.Info("All done!")
}

package main

import (
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/KeyCredentialLink/config"

	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_add"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_associate"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_attach"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_create"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_extract"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_find"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_flush"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_info"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_list"
	"github.com/TheManticoreProject/KeyCredentialLink/modes/mode_remove"

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

	// KeyCredential value to remove
	valueToRemove string
	valueToAdd    string

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
	ap := parser.ArgumentsParser{Banner: "KeyCredentialLink - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0"}
	ap.SetupSubParsing("mode", &mode, true)

	// add ==================================================================================================================
	mode_add.SetupSubParser(&ap, &debug, &distinguishedName, &valueToAdd, &useLdaps, &ldapPort, &domainController, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass)
	// attach ==================================================================================================================
	mode_attach.SetupSubParser(&ap, &debug, &distinguishedName, &pfxPassword, &privateKey, &publicKey, &pfxCertificate)
	// create ==========================================================================================================================
	mode_create.SetupSubParser(&ap, &debug, &distinguishedName, &identifier, &creationTime, &lastLogonTime, &notBeforeTime, &notAfterTime, &deviceId, &keySize, &exportPem, &exportPfx, &useLdaps, &ldapPort, &domainController, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass)
	// extract ==================================================================================================================
	mode_extract.SetupSubParser(&ap, &debug, &distinguishedName, &exportPem, &exportPfx)
	// find ==================================================================================================================
	mode_find.SetupSubParser(&ap, &debug, &distinguishedName)
	// flush ==========================================================================================================================
	mode_flush.SetupSubParser(&ap, &debug, &distinguishedName, &useLdaps, &ldapPort, &domainController, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass)
	// list ==================================================================================================================
	mode_list.SetupSubParser(&ap, &debug, &distinguishedName, &useLdaps, &ldapPort, &domainController, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass)
	// remove ==================================================================================================================
	mode_remove.SetupSubParser(&ap, &debug, &distinguishedName, &valueToRemove, &useLdaps, &ldapPort, &domainController, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass)
	// associate ==================================================================================================================
	mode_associate.SetupSubParser(&ap, &debug, &distinguishedName)

	// Parse arguments
	ap.Parse()

	if !ap.ArgumentIsPresent("--ldap-port") {
		if useLdaps {
			ldapPort = 636
		} else {
			ldapPort = 389
		}
	}
}

func main() {
	parseArgs()

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating credentials struct: %s", err))
	}

	config := config.Config{
		Debug:       debug,
		Credentials: creds,
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

	switch mode {

	case "add":
		err := mode_add.Run(distinguishedName, valueToAdd, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_add: %s", err))
		}

	case "associate":
		err := mode_associate.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_associate: %s", err))
		}

	case "attach":
		err := mode_attach.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_attach: %s", err))
		}

	case "create":
		err := mode_create.Run(distinguishedName, identifier, creationTime, lastLogonTime, notBeforeTime, notAfterTime, deviceId, keySize, exportPem, exportPfx, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_create: %s", err))
		}

	case "extract":
		err := mode_extract.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_extract: %s", err))
		}

	case "flush":
		err := mode_flush.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_flush: %s", err))
		}

	case "info":
		err := mode_info.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_info: %s", err))
		}

	case "list":
		err := mode_list.Run(distinguishedName, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_list: %s", err))
		}

	case "remove":
		err := mode_remove.Run(distinguishedName, valueToRemove, config)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error running mode_remove: %s", err))
		}

	default:
		logger.Warn(fmt.Sprintf("Invalid mode: %s", mode))

	}

	logger.Info("All done!")
}

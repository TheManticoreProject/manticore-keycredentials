package main

import (
	"os"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"

	"github.com/TheManticoreProject/manticore-keycredentials/cli"
	"github.com/TheManticoreProject/manticore-keycredentials/config"

	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_attach"
	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_create"
	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_describe"
	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_enroll"
	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_extract"
	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_find"
	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_flush"
	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_list"
	"github.com/TheManticoreProject/manticore-keycredentials/modes/mode_remove"

	"fmt"
)

var (
	mode string

	distinguishedName string

	// Target selection and safety, shared by the multi-target modes
	targetOptions cli.TargetOptions
	safetyOptions cli.SafetyOptions

	// KeyCredential source
	pfxPassword    string
	pfxCertificate string
	pemFile        string
	exportPem      bool
	exportPfx      bool
	exportDer      bool
	extractOutput  string

	// Certificate build
	subject       string
	identifier    string
	creationTime  string
	lastLogonTime string
	notBeforeTime string
	notAfterTime  string
	deviceId      string
	keySize       int
	createOutput  string

	// Configuration
	debug bool

	// LDAP Connection Settings
	domainController string
	dcHost           string
	ldapPort         int
	useLdaps         bool
	useKerberos      bool
	dnsNameServer    string

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authAesKey   string
	authNoPass   bool
	ticketCCache string
	ticketKirbi  string
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "manticore-keycredentials - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.1.0"}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)
	ap.SetupSubParsing("mode", &mode, true)

	// attach ==================================================================================================================
	mode_attach.SetupSubParser(&ap, &debug, &targetOptions, &safetyOptions, &pfxCertificate, &pfxPassword, &pemFile, &identifier, &creationTime, &lastLogonTime, &deviceId, &domainController, &dcHost, &ldapPort, &useLdaps, &useKerberos, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authAesKey, &authNoPass, &ticketCCache, &ticketKirbi)
	// create ==========================================================================================================================
	mode_create.SetupSubParser(&ap, &debug, &subject, &notBeforeTime, &notAfterTime, &keySize, &createOutput, &pfxPassword)
	// describe ==================================================================================================================
	mode_describe.SetupSubParser(&ap, &debug, &distinguishedName, &domainController, &dcHost, &ldapPort, &useLdaps, &useKerberos, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authAesKey, &authNoPass, &ticketCCache, &ticketKirbi)
	// enroll ==================================================================================================================
	mode_enroll.SetupSubParser(&ap, &debug, &targetOptions, &safetyOptions, &identifier, &creationTime, &lastLogonTime, &notBeforeTime, &notAfterTime, &deviceId, &keySize, &exportPem, &exportPfx, &domainController, &dcHost, &ldapPort, &useLdaps, &useKerberos, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authAesKey, &authNoPass, &ticketCCache, &ticketKirbi)
	// extract ==================================================================================================================
	mode_extract.SetupSubParser(&ap, &debug, &distinguishedName, &extractOutput, &exportPem, &exportDer, &domainController, &dcHost, &ldapPort, &useLdaps, &useKerberos, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authAesKey, &authNoPass, &ticketCCache, &ticketKirbi)
	// find ==================================================================================================================
	mode_find.SetupSubParser(&ap, &debug, &distinguishedName, &pfxCertificate, &pfxPassword, &pemFile, &domainController, &dcHost, &ldapPort, &useLdaps, &useKerberos, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authAesKey, &authNoPass, &ticketCCache, &ticketKirbi)
	// flush ==========================================================================================================================
	mode_flush.SetupSubParser(&ap, &debug, &distinguishedName, &safetyOptions, &domainController, &dcHost, &ldapPort, &useLdaps, &useKerberos, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authAesKey, &authNoPass, &ticketCCache, &ticketKirbi)
	// list ==================================================================================================================
	mode_list.SetupSubParser(&ap, &debug, &targetOptions, &domainController, &dcHost, &ldapPort, &useLdaps, &useKerberos, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authAesKey, &authNoPass, &ticketCCache, &ticketKirbi)
	// remove ==================================================================================================================
	mode_remove.SetupSubParser(&ap, &debug, &targetOptions, &safetyOptions, &pfxCertificate, &pfxPassword, &pemFile, &domainController, &dcHost, &ldapPort, &useLdaps, &useKerberos, &dnsNameServer, &authDomain, &authUsername, &authPassword, &authHashes, &authAesKey, &authNoPass, &ticketCCache, &ticketKirbi)

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

	// The logger emits every level by default, so --debug has to raise the floor
	// itself: without this, logger.Debug output appears in runs that did not ask for
	// it. LevelPrint sits above all others, so results are never filtered either way.
	if debug {
		logger.SetLevel(logger.LevelDebug)
	} else {
		logger.SetLevel(logger.LevelInfo)
	}

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating credentials struct: %s", err))
		os.Exit(1)
	}

	// An AES key is only usable over Kerberos, so requesting one implies -k rather
	// than being a separate choice the caller has to remember to make.
	if len(authAesKey) > 0 {
		if err := creds.SetAESKey(authAesKey); err != nil {
			logger.Warn(fmt.Sprintf("Error setting AES key: %s", err))
			os.Exit(1)
		}
		if !useKerberos {
			logger.Debug("An AES key was supplied, enabling Kerberos authentication")
			useKerberos = true
		}
	}

	// A Kerberos ticket (ccache or .kirbi) is itself the credential for
	// pass-the-ticket and only works over Kerberos, so supplying one implies -k,
	// just like an AES key.
	if len(ticketCCache) > 0 {
		if err := creds.SetCCache(ticketCCache); err != nil {
			logger.Warn(fmt.Sprintf("Error setting ccache: %s", err))
			os.Exit(1)
		}
	}
	if len(ticketKirbi) > 0 {
		if err := creds.SetKirbi(ticketKirbi); err != nil {
			logger.Warn(fmt.Sprintf("Error setting kirbi: %s", err))
			os.Exit(1)
		}
	}
	if len(ticketCCache) > 0 || len(ticketKirbi) > 0 {
		if !useKerberos {
			logger.Debug("A Kerberos ticket was supplied, enabling Kerberos authentication")
			useKerberos = true
		}
	}

	// --no-pass only states that no password is coming; the required Secret group
	// guarantees one of the other secrets was supplied, so there is nothing left to
	// check here. It stays accepted for callers that pass it alongside a ticket.

	config := config.Config{
		Debug:       debug,
		Credentials: creds,
		Network: config.Network{
			LDAP: config.LDAP{
				UseLdaps:    useLdaps,
				UseKerberos: useKerberos,
				LDAPPort:    ldapPort,
				SPNHostname: dcHost,
			},
			DNSNameServer:    dnsNameServer,
			DomainController: domainController,
			Domain:           authDomain,
		},
	}

	// A mode that fails must be reflected in the exit code so a caller can detect
	// it, rather than always exiting 0.
	if err := dispatch(config); err != nil {
		logger.Warn(fmt.Sprintf("Error running mode_%s: %s", mode, err))
		logger.Print("Done.")
		os.Exit(1)
	}

	logger.Print("Done.")
}

// dispatch runs the selected mode and returns its error.
//
// Parameters:
//
//	config (config.Config): The configuration of the application.
//
// Returns:
//
//	The error returned by the mode, or an error for an unknown mode.
func dispatch(config config.Config) error {
	switch mode {
	case "attach":
		return mode_attach.Run(targetOptions, safetyOptions, pfxCertificate, pfxPassword, pemFile, identifier, creationTime, lastLogonTime, deviceId, config)
	case "create":
		return mode_create.Run(subject, notBeforeTime, notAfterTime, keySize, createOutput, pfxPassword, config)
	case "describe":
		return mode_describe.Run(distinguishedName, config)
	case "enroll":
		return mode_enroll.Run(targetOptions, safetyOptions, identifier, creationTime, lastLogonTime, notBeforeTime, notAfterTime, deviceId, keySize, exportPem, exportPfx, config)
	case "extract":
		return mode_extract.Run(distinguishedName, extractOutput, exportPem, exportDer, config)
	case "find":
		return mode_find.Run(distinguishedName, pfxCertificate, pfxPassword, pemFile, config)
	case "flush":
		return mode_flush.Run(distinguishedName, safetyOptions, config)
	case "list":
		return mode_list.Run(targetOptions, config)
	case "remove":
		return mode_remove.Run(targetOptions, safetyOptions, pfxCertificate, pfxPassword, pemFile, config)
	default:
		return fmt.Errorf("invalid mode '%s'", mode)
	}
}

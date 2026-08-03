// Package utils holds the helpers shared between the tool's modes.
//
// Only connection and lookup logic is shared here. Result rendering is written
// inline in each mode, with the ANSI escapes in the format string, so that every
// line reads as exactly what it prints.
package utils

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	ldapv3 "github.com/go-ldap/ldap/v3"
)

// NewLDAPSession creates an LDAP session and connects it to the domain controller.
//
// Parameters:
//
//	domainController (string): The hostname or IP address of the domain controller.
//	ldapPort (int): The port number to connect to on the LDAP server.
//	creds (*credentials.Credentials): The credentials for authentication.
//	useLdaps (bool): A flag indicating whether to use LDAPS instead of LDAP.
//	useKerberos (bool): A flag indicating whether to use Kerberos instead of NTLM.
//	spnHostname (string): The FQDN to build the Kerberos ldap SPN from when the
//	  domain controller is reached by IP; empty uses the connection host.
//
// Returns:
//
//	A connected LDAP session, or an error if the session could not be created or
//	connected.
func NewLDAPSession(domainController string, ldapPort int, creds *credentials.Credentials, useLdaps bool, useKerberos bool, spnHostname string) (*ldap.Session, error) {
	ldapSession, err := ldap.NewSession(domainController, ldapPort, creds, useLdaps, useKerberos)
	if err != nil {
		return nil, fmt.Errorf("error creating LDAP session: %s", err)
	}

	// A Kerberos bind to a DC named by IP needs the FQDN in the SPN. Set before
	// connecting; it is a no-op for the non-Kerberos and empty cases.
	if useKerberos && spnHostname != "" {
		ldapSession.SetKerberosSPNHostname(spnHostname)
	}

	connected, err := ldapSession.Connect()
	if err != nil {
		return nil, fmt.Errorf("error connecting to LDAP server: %s", err)
	}
	if !connected {
		return nil, fmt.Errorf("error connecting to LDAP server")
	}

	return ldapSession, nil
}

// LogConnection logs the identity and URL the session is connected as, for debug
// output.
//
// Parameters:
//
//	domain (string): The domain of the authenticated user.
//	username (string): The authenticated user.
//	domainController (string): The hostname or IP address of the domain controller.
//	ldapPort (int): The port number connected to on the LDAP server.
//	useLdaps (bool): A flag indicating whether LDAPS is in use.
func LogConnection(domain, username, domainController string, ldapPort int, useLdaps bool) {
	scheme := "ldap"
	if useLdaps {
		scheme = "ldaps"
	}
	logger.Debug(fmt.Sprintf("Connected as '%s\\%s' on %s://%s:%d", domain, username, scheme, domainController, ldapPort))
}

// FindUniqueObject looks up the single object matching a distinguished name.
//
// It is an error for the search to match no object, or more than one: every mode
// that targets a distinguished name expects exactly one result.
//
// Parameters:
//
//	ldapSession (*ldap.Session): The connected LDAP session to query.
//	distinguishedName (string): The distinguished name of the target object.
//	attributes ([]string): The attributes to request for the object.
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	The matching LDAP entry, or an error if the search failed or did not match
//	exactly one object.
func FindUniqueObject(ldapSession *ldap.Session, distinguishedName string, attributes []string, debug bool) (*ldapv3.Entry, error) {
	query := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)
	if debug {
		logger.Debug(fmt.Sprintf("Querying ldap: %s", query))
	}

	ldapResults, err := ldapSession.QueryWholeSubtree("", query, attributes)
	if err != nil {
		return nil, fmt.Errorf("error querying LDAP server: %s", err)
	}

	if len(ldapResults) == 0 {
		logger.Warn(fmt.Sprintf("No objects with distinguishedName '%s' found.", distinguishedName))
		return nil, fmt.Errorf("no objects with distinguishedName '%s' found", distinguishedName)
	}

	if len(ldapResults) > 1 {
		logger.Warn(fmt.Sprintf("More than one object with distinguishedName '%s' found (%d).", distinguishedName, len(ldapResults)))
		if debug {
			for _, entry := range ldapResults {
				logger.Debug(fmt.Sprintf(" | %s", entry.GetAttributeValue("distinguishedName")))
			}
		}
		return nil, fmt.Errorf("more than one object with distinguishedName '%s' found (%d)", distinguishedName, len(ldapResults))
	}

	return ldapResults[0], nil
}

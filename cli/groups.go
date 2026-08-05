// Package cli holds the argument groups shared between the tool's modes.
//
// goopts does not inherit flags from a parent parser: every flag has to be
// registered on each sub-parser that uses it. These helpers register a whole
// group at once so the modes do not each carry their own copy of the same
// declarations.
package cli

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
)

// RegisterConfigurationGroup registers the "Configuration" argument group on a
// sub-parser.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	debug (*bool): Whether to print debug information.
func RegisterConfigurationGroup(subparser *parser.ArgumentsParser, debug *bool) {
	group, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")
}

// RegisterLDAPConnectionSettingsGroup registers the "LDAP Connection Settings"
// argument group on a sub-parser.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	domainController (*string): The hostname or IP address of the domain controller.
//	ldapPort (*int): The port to connect to on the LDAP server.
//	useLdaps (*bool): Whether to use LDAPS instead of LDAP.
//	useKerberos (*bool): Whether to use Kerberos instead of NTLM.
//	dnsNameServer (*string): The DNS name server to resolve names with.
func RegisterLDAPConnectionSettingsGroup(subparser *parser.ArgumentsParser, domainController *string, dcHost *string, ldapPort *int, useLdaps *bool, useKerberos *bool, dnsNameServer *string) {
	group, err := subparser.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(domainController, "-dc", "--dc-ip", "", false, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
	group.NewStringArgument(dcHost, "", "--dc-host", "", false, "FQDN of the domain controller, used to build the Kerberos SPN when connecting by IP with -k.")
	group.NewTcpPortArgument(ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
	group.NewBoolArgument(useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
	group.NewBoolArgument(useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	group.NewStringArgument(dnsNameServer, "", "--dns-name-server", "", false, "DNS name server to use.")
}

// RegisterAuthenticationGroup registers the "Authentication" argument group on a
// sub-parser.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	authDomain (*string): The (FQDN) domain to authenticate to.
//	authUsername (*string): The user to authenticate as.
//	authNoPass (*bool): Whether to skip asking for a password.
func RegisterAuthenticationGroup(subparser *parser.ArgumentsParser, authDomain *string, authUsername *string, authNoPass *bool) {
	group, err := subparser.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(authDomain, "-d", "--domain", "", false, "Active Directory domain to authenticate to.")
	group.NewStringArgument(authUsername, "-u", "--username", "", false, "User to authenticate as.")
	// --no-pass selects "no password", it does not supply a secret, so it does not
	// belong in the mutually exclusive Secret group: it has to be combinable with the
	// ticket it accompanies.
	group.NewBoolArgument(authNoPass, "", "--no-pass", false, "Don't ask for password, the secret is a Kerberos ticket (--ticket-ccache or --ticket-kirbi).")
}

// RegisterSecretGroup registers the "Secret" argument group on a sub-parser. The
// group is mutually exclusive and required: exactly one secret has to be provided.
//
// --no-pass is not part of this group. It selects "no password" rather than being a
// secret of its own, so it lives in the Authentication group and stays combinable
// with the ticket that carries the actual credential.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	authPassword (*string): The password to authenticate with.
//	authHashes (*string): The LM:NT hashes to authenticate with.
//	authAesKey (*string): The AES key to authenticate with.
//	ticketCCache (*string): Path to a Kerberos credential cache (ccache) holding a TGT.
//	ticketKirbi (*string): Path to a .kirbi file holding a TGT.
func RegisterSecretGroup(subparser *parser.ArgumentsParser, authPassword *string, authHashes *string, authAesKey *string, ticketCCache *string, ticketKirbi *string) {
	group, err := subparser.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
	group.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	group.NewStringArgument(authAesKey, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	group.NewStringArgument(ticketCCache, "", "--ticket-ccache", "", false, "Path to a Kerberos credential cache (ccache) holding a TGT for pass-the-ticket (implies -k).")
	group.NewStringArgument(ticketKirbi, "", "--ticket-kirbi", "", false, "Path to a .kirbi file holding a TGT for pass-the-ticket (implies -k).")
}

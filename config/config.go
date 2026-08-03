package config

import "github.com/TheManticoreProject/Manticore/windows/credentials"

type Config struct {
	// General
	Debug bool
	// Credentials
	Credentials *credentials.Credentials
	// Network
	Network Network
}

type LDAP struct {
	UseLdaps    bool
	UseKerberos bool
	LDAPPort    int
	// SPNHostname overrides the hostname used to build the Kerberos ldap SPN when
	// the domain controller is reached by IP. Empty means use the connection host.
	SPNHostname string
}

type Network struct {
	LDAP             LDAP
	DomainController string
	Domain           string
	DNSNameServer    string
}

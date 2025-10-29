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
	UseLdaps bool
	LDAPPort int
}

type Network struct {
	LDAP             LDAP
	DomainController string
	Domain           string
	DNSNameServer    string
}

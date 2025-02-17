package config

type Config struct {
	// General
	Debug bool
	// Credentials
	Credentials Credentials
	// Network
	Network Network
}

type Credentials struct {
	Username string
	Domain   string
	Password string
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

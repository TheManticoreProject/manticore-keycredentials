package ldap

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const UnixTimestampStart int64 = 116444736000000000 // Monday, January 1, 1601 12:00:00 AM

// GetDomainFromDistinguishedName returns the domain from a distinguished name.
//
// Parameters:
// - distinguishedName: A string representing the distinguished name.
//
// Returns:
// - A string representing the domain.
func GetDomainFromDistinguishedName(distinguishedName string) string {
	domainParts := strings.Split(distinguishedName, ",")

	domain := ""
	for _, part := range domainParts {
		if strings.HasPrefix(part, "DC=") {
			domain += strings.TrimPrefix(part, "DC=") + "."
		}
	}

	domain = strings.TrimSuffix(domain, ".")

	return domain
}

// ConvertLDAPTimeStampToUnixTimeStamp converts an LDAP timestamp to a Unix timestamp.
//
// Parameters:
// - value: A string representing the LDAP timestamp.
//
// Returns:
// - An int64 value representing the Unix timestamp.
func ConvertLDAPTimeStampToUnixTimeStamp(value string) int64 {
	convertedValue := int64(0)

	if len(value) != 0 {
		valueInt, err := strconv.ParseInt(value, 10, 64)

		if err != nil {
			fmt.Printf("[!] Error converting value to int64: %s\n", err)
			return convertedValue
		}

		if valueInt < UnixTimestampStart {
			// Typically for dates on year 1601
			convertedValue = 0
		} else {
			delta := int64((valueInt - UnixTimestampStart) * 100)
			convertedValue = int64(time.Unix(0, delta).Unix())
		}
	}

	return convertedValue
}

// ConvertLDAPDurationToSeconds converts an LDAP duration to a Unix timestamp.
//
// Parameters:
// - value: A string representing the LDAP duration.
//
// Returns:
// - An int64 value representing the Unix timestamp.
func ConvertLDAPDurationToSeconds(value string) int64 {
	convertedValue := int64(0)

	if len(value) != 0 {
		valueInt, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			fmt.Printf("[!] Error converting value to int64: %s\n", err)
			return convertedValue
		}

		if valueInt < 0 {
			valueInt = valueInt * int64(-1)
		}

		// Convert intervals of 100-nanoseconds to Seconds
		convertedValue = valueInt / int64(1e7)
	}

	return convertedValue
}

// ConvertSecondsToLDAPDuration converts a Unix timestamp to an LDAP duration.
//
// Parameters:
// - value: An int64 value representing the Unix timestamp.
//
// Returns:
// - A string representing the LDAP duration.
func ConvertSecondsToLDAPDuration(value int64) string {
	convertedValue := fmt.Sprintf("%d", value*int64(1e7))
	return convertedValue
}

// ConvertUnixTimeStampToLDAPTimeStamp converts a Unix timestamp to an LDAP timestamp.
//
// Parameters:
// - value: A time.Time object representing the Unix timestamp.
//
// Returns:
// - An int64 value representing the LDAP timestamp.
func ConvertUnixTimeStampToLDAPTimeStamp(value time.Time) int64 {
	ldapvalue := value.Unix() * (1e7)
	ldapvalue = ldapvalue + UnixTimestampStart
	return int64(ldapvalue)
}

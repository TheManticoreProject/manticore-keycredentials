package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/goopts/parser"
	ldapv3 "github.com/go-ldap/ldap/v3"
)

// TargetOptions holds the flags that select which objects a mode operates on.
//
// A mode may target a single object by its distinguished name, every object
// matching an LDAP filter, or every distinguished name listed in a file. goopts
// has no list argument, so these three flags stand in for a repeatable target.
type TargetOptions struct {
	DistinguishedName string
	Filter            string
	TargetsFile       string
}

// Empty reports whether no target selector was given, which a mode may treat as a
// request for a default set (for example, every object holding the attribute).
//
// Returns:
//
//	True when none of the three selectors is set.
func (o TargetOptions) Empty() bool {
	return o.DistinguishedName == "" && o.Filter == "" && o.TargetsFile == ""
}

// RegisterTargetGroup registers the "Targets" argument group on a sub-parser, for
// the modes that act on one or more objects.
//
// The three flags are not mutually exclusive at the parser level, because a
// clearer message can be given at resolution time than goopts' generic one, and
// because leaving them independent keeps the registration a single call.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	options (*TargetOptions): The target flag storage to bind to.
func RegisterTargetGroup(subparser *parser.ArgumentsParser, options *TargetOptions) {
	group, err := subparser.NewArgumentGroup("Targets")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewStringArgument(&options.DistinguishedName, "-D", "--distinguished-name", "", false, "Distinguished name of a single target object.")
	group.NewStringArgument(&options.Filter, "-f", "--filter", "", false, "LDAP filter selecting the target objects.")
	group.NewStringArgument(&options.TargetsFile, "-tf", "--targets-file", "", false, "File containing one target distinguished name per line.")
}

// ValidateTargets checks that exactly one target selector was supplied, without
// contacting the directory, so a mode can fail fast before it connects.
//
// Parameters:
//
//	options (TargetOptions): The resolved target flags.
//
// Returns:
//
//	An error if the number of selectors provided is not one.
func ValidateTargets(options TargetOptions) error {
	_, err := targetFilter(options)
	return err
}

// ResolveTargets turns the target options into the set of objects a mode operates
// on, by querying the directory once for each selector and requesting attributes.
//
// Exactly one selector must be provided. The distinguished names collected from a
// targets file are OR'd into a single filter so the directory is queried once
// rather than per line, and every result is de-duplicated by distinguished name so
// overlapping selectors cannot make a mode act on the same object twice.
//
// Parameters:
//
//	ldapSession (*ldap.Session): The connected LDAP session to query.
//	options (TargetOptions): The resolved target flags.
//	attributes ([]string): The attributes to request for each object.
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	The matching LDAP entries, or an error if no selector or more than one selector
//	was given, if a targets file cannot be read, or if the query fails.
func ResolveTargets(ldapSession *ldap.Session, options TargetOptions, attributes []string, debug bool) ([]*ldapv3.Entry, error) {
	filter, err := targetFilter(options)
	if err != nil {
		return nil, err
	}

	if debug {
		logger.Debug(fmt.Sprintf("Querying ldap: %s", filter))
	}

	results, err := ldapSession.QueryWholeSubtree("", filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("error querying LDAP server: %s", err)
	}

	return dedupeByDistinguishedName(results), nil
}

// targetFilter builds the single LDAP filter that selects the target objects from
// whichever one selector was provided.
//
// Parameters:
//
//	options (TargetOptions): The resolved target flags.
//
// Returns:
//
//	The LDAP filter, or an error if the number of selectors provided is not one.
func targetFilter(options TargetOptions) (string, error) {
	selectors := 0
	for _, set := range []bool{options.DistinguishedName != "", options.Filter != "", options.TargetsFile != ""} {
		if set {
			selectors++
		}
	}

	switch {
	case selectors == 0:
		return "", fmt.Errorf("no target selected: set one of --distinguished-name, --filter or --targets-file")
	case selectors > 1:
		return "", fmt.Errorf("more than one target selector set: use only one of --distinguished-name, --filter or --targets-file")
	}

	switch {
	case options.DistinguishedName != "":
		safeDN := ldapv3.EscapeFilter(options.DistinguishedName)
		return fmt.Sprintf("(distinguishedName=%s)", safeDN), nil

	case options.Filter != "":
		return options.Filter, nil

	default:
		distinguishedNames, err := readTargetsFile(options.TargetsFile)
		if err != nil {
			return "", err
		}
		if len(distinguishedNames) == 0 {
			return "", fmt.Errorf("targets file '%s' holds no distinguished name", options.TargetsFile)
		}
		var builder strings.Builder
		builder.WriteString("(|")
		for _, dn := range distinguishedNames {
			safeDN := ldapv3.EscapeFilter(dn)
			builder.WriteString(fmt.Sprintf("(distinguishedName=%s)", safeDN))
		}
		builder.WriteString(")")
		return builder.String(), nil
	}
}

// readTargetsFile reads a file of one distinguished name per line, ignoring blank
// lines and lines beginning with '#' so a targets file can carry comments.
//
// Parameters:
//
//	path (string): The path to the targets file.
//
// Returns:
//
//	The distinguished names, or an error if the file cannot be read.
func readTargetsFile(path string) ([]string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read targets file: %s", err)
	}
	defer handle.Close()

	distinguishedNames := []string{}
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		distinguishedNames = append(distinguishedNames, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading targets file: %s", err)
	}

	return distinguishedNames, nil
}

// dedupeByDistinguishedName drops entries whose distinguished name has already been
// seen, keeping the first occurrence and its original order.
//
// Parameters:
//
//	entries ([]*ldapv3.Entry): The entries to de-duplicate.
//
// Returns:
//
//	The entries with later duplicates removed.
func dedupeByDistinguishedName(entries []*ldapv3.Entry) []*ldapv3.Entry {
	seen := map[string]bool{}
	unique := make([]*ldapv3.Entry, 0, len(entries))
	for _, entry := range entries {
		dn := entry.GetAttributeValue("distinguishedName")
		if seen[dn] {
			continue
		}
		seen[dn] = true
		unique = append(unique, entry)
	}
	return unique
}

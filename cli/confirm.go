package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
)

// SafetyOptions holds the flags that guard a write acting on several objects.
type SafetyOptions struct {
	AssumeYes bool
}

// removedSafetyFlags are Safety flags the write modes used to accept, mapped to what
// to tell a caller still passing one.
//
// goopts ignores an argument it does not know rather than refusing it, so dropping
// --dry-run silently turns a stale "preview" invocation into a real write that
// reports success. Refusing the flag outright keeps that from happening, the same way
// create refuses the Active Directory flags it no longer accepts.
var removedSafetyFlags = map[string]string{
	"--dry-run": "--dry-run has been removed; the objects a run resolved are printed before anything is written, and -y/--yes controls the confirmation prompt",
}

// CheckRemovedSafetyFlags returns an error when the argument list still carries a
// Safety flag that no longer exists.
//
// The `--flag=value` form is handled by comparing only the part before the '='.
//
// Parameters:
//
//	args ([]string): The process arguments, including the program name and mode.
//
// Returns:
//
//	An error naming the removed flag, or nil when none is present.
func CheckRemovedSafetyFlags(args []string) error {
	// Skip the program name and the mode selector.
	start := 2
	if len(args) < start {
		start = len(args)
	}

	for _, arg := range args[start:] {
		flag := arg
		if i := strings.IndexByte(flag, '='); i >= 0 {
			flag = flag[:i]
		}
		if message, ok := removedSafetyFlags[flag]; ok {
			return errors.New(message)
		}
	}

	return nil
}

// RegisterSafetyGroup registers the "Safety" argument group on a sub-parser, for
// the write modes that can act on more than one object.
//
// Parameters:
//
//	subparser (*parser.ArgumentsParser): The parser to register the group on.
//	options (*SafetyOptions): The safety flag storage to bind to.
func RegisterSafetyGroup(subparser *parser.ArgumentsParser, options *SafetyOptions) {
	group, err := subparser.NewArgumentGroup("Safety")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
		return
	}
	group.NewBoolArgument(&options.AssumeYes, "-y", "--yes", false, "Do not prompt for confirmation before acting on more than one object.")
}

// ConfirmWrite decides whether a write acting on targetCount objects should go
// ahead.
//
// A single object proceeds without a prompt, since the caller named exactly one
// thing. Acting on more than one object prompts for confirmation unless --yes was
// given; the prompt defaults to no, and a closed or non-interactive stdin counts as
// no so an unattended run cannot mass-modify by waiting on input that never comes.
//
// Parameters:
//
//	action (string): A short description of what will be done, e.g. "attach a certificate to".
//	targetCount (int): The number of objects that would be written to.
//	options (SafetyOptions): The resolved safety flags.
//
// Returns:
//
//	True if the caller should proceed with the writes.
func ConfirmWrite(action string, targetCount int, options SafetyOptions) bool {
	if targetCount <= 1 || options.AssumeYes {
		return true
	}

	logger.Warn(fmt.Sprintf("About to %s %d objects.", action, targetCount))
	fmt.Fprint(os.Stderr, "[?] Proceed? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		logger.Warn("No confirmation received, aborting.")
		return false
	}

	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "y" || answer == "yes" {
		return true
	}

	logger.Warn("Aborted.")
	return false
}

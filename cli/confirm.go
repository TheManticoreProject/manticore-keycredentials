package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
)

// SafetyOptions holds the flags that guard a write acting on several objects.
type SafetyOptions struct {
	DryRun    bool
	AssumeYes bool
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
	group.NewBoolArgument(&options.DryRun, "", "--dry-run", false, "Resolve the target objects and show what would happen, without making any change.")
	group.NewBoolArgument(&options.AssumeYes, "-y", "--yes", false, "Do not prompt for confirmation before acting on more than one object.")
}

// ConfirmWrite decides whether a write acting on targetCount objects should go
// ahead.
//
// A dry run never proceeds. A single object proceeds without a prompt, since the
// caller named exactly one thing. Acting on more than one object prompts for
// confirmation unless --yes was given; the prompt defaults to no, and a closed or
// non-interactive stdin counts as no so an unattended run cannot mass-modify by
// waiting on input that never comes.
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
	if options.DryRun {
		logger.Info(fmt.Sprintf("Dry run: would %s %d object(s); no change made.", action, targetCount))
		return false
	}

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

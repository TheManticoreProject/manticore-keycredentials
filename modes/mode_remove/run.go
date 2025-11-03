package mode_remove

import (
	"github.com/TheManticoreProject/Manticore/logger"

	"github.com/TheManticoreProject/ShadowCredentials/config"
)

// Run removes a KeyCredentialLink from a user.
//
// Parameters:
// - distinguishedName: The distinguished name of the user.
// - config: The configuration of the application.
//
// Returns:
// - An error if the operation fails.
// - nil if the operation succeeds.
func Run(distinguishedName string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'remove'")
	}

	return nil
}

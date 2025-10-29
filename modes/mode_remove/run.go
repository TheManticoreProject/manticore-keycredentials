package mode_remove

import (
	"github.com/TheManticoreProject/Manticore/logger"

	"github.com/TheManticoreProject/ShadowCredentials/config"
)

func Run(distinguishedName string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'remove'")
	}

	return nil
}

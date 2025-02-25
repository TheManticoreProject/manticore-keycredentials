package mode_attach

import (
	"shadowcredentials/core/config"
	"shadowcredentials/logger"
)

func Run(distinguishedName string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'attach'")
	}

	return nil
}

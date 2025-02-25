package mode_extract

import (
	"shadowcredentials/core/config"
	"shadowcredentials/logger"
)

func Run(distinguishedName string, config config.Config) error {
	if config.Debug {
		logger.Debug("Starting mode 'extract'")
	}

	return nil
}

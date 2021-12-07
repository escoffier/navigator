// Package logging is to define our logger
package logging

import (
	"gitlab.com/security-rd/go-pkg/logging"
)

type Logger = logging.Logger

// SetVerbose is to enable the zerolog to debug level.
func SetVerbose() {
	logging.SetVerbose()
}

// GetLogger to return the global logger.
func GetLogger() *logging.Logger {
	return logging.Get()
}

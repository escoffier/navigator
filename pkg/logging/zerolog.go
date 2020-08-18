// Package logging is to define our logger
package logging

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

var (
	log Logger
)

func init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	output := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		NoColor:    true,
		TimeFormat: time.RFC3339,
		FormatLevel: func(i interface{}) string {
			return strings.ToUpper(fmt.Sprintf("%s:", i))
		},
	}
	log = Logger{
		zerolog.New(output).With().Timestamp().Caller().Logger(),
	}
}

// Logger is the wrapper of zerolog.Logger
type Logger struct {
	zerolog.Logger
}

// SetVerbose is to enable the zerolog to debug level.
func SetVerbose() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
}

// Disable is to disable the loggin altogether.
func Disable() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

// GetLogger to return the global logger.
func GetLogger() *Logger {
	return &log
}

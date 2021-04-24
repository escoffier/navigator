// Package logging is to define our logger
package logging

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

var (
	log Logger
)

const (
	CtxKeyLogID = "CTX_ts_logid"
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

type LoggerWrapper struct {
	l   *Logger
	ctx context.Context
}

func getFormatWithLogIDFromCtx(ctx context.Context, format string) string {
	if ctx == nil {
		return format
	}
	ldval := ctx.Value(CtxKeyLogID)
	if logid, ok := ldval.(string); ok {
		sb := strings.Builder{}
		sb.WriteString(logid)
		sb.WriteString(" ")
		sb.WriteString(format)
		return sb.String()
	}
	return format
}
func (lw LoggerWrapper) Infof(fmt string, v ...interface{}) {
	format := getFormatWithLogIDFromCtx(lw.ctx, fmt)
	lw.l.Info().Msgf(format, v...)
}

func (lw LoggerWrapper) Warnf(fmt string, v ...interface{}) {
	format := getFormatWithLogIDFromCtx(lw.ctx, fmt)
	lw.l.Warn().Msgf(format, v...)
}

func (lw LoggerWrapper) Errorf(err error, fmt string, v ...interface{}) {
	format := getFormatWithLogIDFromCtx(lw.ctx, fmt)
	if err == nil {
		lw.l.Error().Msgf(format, v...)
	} else {
		lw.l.Err(err).Msgf(format, v...)
	}
}

func (l *Logger) WithContext(ctx context.Context) LoggerWrapper {
	return LoggerWrapper{
		l:   l,
		ctx: ctx,
	}
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

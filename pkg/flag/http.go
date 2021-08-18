// Package flag can help in making the command line arguments more consistent by having the
// arguments in one place for different thirdparty libraries:
// e.g. elasticsearch, mongo, and etcd
package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	httpWebHookListen  = "http-web-hook-listen"
	httpListen         = "http-listen"
	httpLoggerDisabled = "http-logger-disabled"
)

// HTTPOpts the http options.
type HTTPOpts struct {
	HTTPWebHookListen  string
	HTTPListen         string
	HTTPLoggerDisabled bool
}

// NewDefaultHTTPOpts returns a new default http options.
func NewDefaultHTTPOpts() *HTTPOpts {
	return &HTTPOpts{
		HTTPWebHookListen:  ":8081",
		HTTPListen:         ":8080",
		HTTPLoggerDisabled: false,
	}
}

// GetHTTPOpts parses the cobra.Command and returns the HTTPOpts.
func GetHTTPOpts(cmd *cobra.Command) *HTTPOpts {
	return &HTTPOpts{
		HTTPWebHookListen: viper.GetString(httpWebHookListen),
		HTTPListen:        viper.GetString(httpListen),
	}
}

// AddHTTPFlags adds the http-specific command line arguments to the cobra.Command.
func AddHTTPFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultHTTPOpts()
	cmd.Flags().String(httpWebHookListen, defaultOpts.HTTPWebHookListen, "HTTP web hook listen address")
	cmd.Flags().String(httpListen, defaultOpts.HTTPListen, "HTTP listen address")
	cmd.Flags().Bool(httpLoggerDisabled, defaultOpts.HTTPLoggerDisabled,
		"True if HTTP Logger should be disabled")
	for _, flag := range []string{httpListen, httpLoggerDisabled, httpWebHookListen} {
		err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}

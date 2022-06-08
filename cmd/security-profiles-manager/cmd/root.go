// Package cmd is for all the Cobra commands
package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/api"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
)

var loggingOptions *logging.Options

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "security-profiles-manager",
	Short: "Security Profiles Manager",
	Long:  `Security Profiles Manager`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if errs := loggingOptions.Validate(); len(errs) > 0 {
			return fmt.Errorf("%v", errs)
		}

		// 建议移除verbose
		// 使用log-level调节日志输出等级
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			loggingOptions.Level = int(zerolog.DebugLevel)
		}

		loggingOptions.SetConsoleWriterWrapper(logging.ConsoleCallerWriter)
		logging.ReplaceLogger(loggingOptions)

		logging.Get().Info().
			Str("version", Version).
			Msg("starting Vegeta Console")

		httpOpts := flag.GetHTTPOpts(cmd)
		logging.Get().Info().
			Str("listen", httpOpts.HTTPListen).
			Msg("HTTP options")

		stanOpts := flag.GetStanOptsFromEnv()
		logging.Get().Info().
			Str("cluster-id", stanOpts.ClusterID).
			Msg("STAN options")

		app, err := api.NewSecProfileManager(httpOpts, stanOpts)
		if err != nil {
			return err
		}

		lifecycle.NewApplication(
			app,
		).Run()

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logging.Get().Error().Err(err).Msg("Failed to startup")
		os.Exit(1)
	}
}

func init() {
	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(rootCmd.Flags())

	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")

	flag.AddHTTPFlags(rootCmd)
	// flag.AddRedisFlags(rootCmd)
	// flag.AddStanFlags(rootCmd)
	// flag.AddRDBFlags(rootCmd)

	flag.ConfigViper()
}

// Package cmd is for all the Cobra commands
package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/api"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "security-profiles-manager",
	Short: "Security Profiles Manager",
	Long:  `Security Profiles Manager`,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			logging.SetVerbose()
		}

		logging.GetLogger().Info().
			Str("version", Version).
			Msg("starting Vegeta Console")

		httpOpts := flag.GetHTTPOpts(cmd)
		logging.GetLogger().Info().
			Str("listen", httpOpts.HTTPListen).
			Msg("HTTP options")

		stanOpts := flag.GetStanOptsFromEnv()
		logging.GetLogger().Info().
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
		logging.GetLogger().Error().Err(err).Msg("Failed to startup")
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")

	flag.AddHTTPFlags(rootCmd)
	// flag.AddRedisFlags(rootCmd)
	// flag.AddStanFlags(rootCmd)
	// flag.AddRDBFlags(rootCmd)

	flag.ConfigViper()
}

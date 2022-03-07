// Package cmd is for all the Cobra commands
package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "console",
	Short: "The centralized server",
	Long:  `The centralized server`,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			logging.SetVerbose()
		}

		logging.GetLogger().Info().
			Str("version", Version).
			Msg("starting Console")

		httpOpts := flag.GetHTTPOpts(cmd)
		logging.GetLogger().Info().
			Str("listen", httpOpts.HTTPListen).
			Str("webhooklisten", httpOpts.HTTPWebHookListen).
			Msg("HTTP options")

		rdbOpts := flag.GetRDBOpts(cmd)
		logging.GetLogger().Info().
			Str("pvc", rdbOpts.PVC).
			Str("pod", rdbOpts.Pod).
			Str("dataPath", rdbOpts.DataPath).
			Msg("Postgres options")

		scannerOpts := flag.GetVegetaScannerOpts(cmd)
		logging.GetLogger().Info().
			Str("host", scannerOpts.Host).
			Int("port", scannerOpts.Port).
			Msg("Scanner options")

		scapOpts := flag.GetScapOpts(cmd)
		logging.GetLogger().Info().
			Int32("policy-counts", scapOpts.PolicyCounts).
			Msg("Scap options")

		harborOpts := flag.GetHarborOpts(cmd)
		logging.GetLogger().Info().
			Str("harbor-url", harborOpts.URL).
			Str("harbor-username", harborOpts.Username).
			Bool("harbor-skiptlsverify", harborOpts.SkipTLSVerify).
			Msg("Harbor REST client options")

		elasticOpts := flag.GetElasticOpts(cmd)
		logging.GetLogger().Info().
			Str("host", elasticOpts.Host).
			Str("port", elasticOpts.Port).
			Str("index", elasticOpts.Index).
			Str("username", elasticOpts.Username).
			Msg("Elastic options")

		secProfilesOpts := flag.GetSecProfilesOpts(cmd)
		logging.GetLogger().Info().
			Str("host", secProfilesOpts.Host).
			Int("port", secProfilesOpts.Port).
			Msg("Security Profiles options")

		console, err := service.NewConsole(httpOpts, rdbOpts, scannerOpts, scapOpts, elasticOpts, secProfilesOpts)

		if err != nil {
			return err
		}

		lifecycle.NewApplication(
			console,
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
	flag.AddRDBFlags(rootCmd)
	flag.AddVegetaScannerFlags(rootCmd)
	flag.AddScapFlags(rootCmd)
	flag.AddRedisFlags(rootCmd)
	flag.AddElasticFlags(rootCmd)
	flag.AddHarborFlags(rootCmd)
	flag.AddSecProfilesOpts(rootCmd)
	flag.AddClusterManagerFlags(rootCmd)
	flag.AddWebHookFlags(rootCmd)

	flag.ConfigViper()
}

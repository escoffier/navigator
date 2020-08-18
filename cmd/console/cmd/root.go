// Package cmd is for all the Cobra commands
package cmd

import (
	"fmt"
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
			Msg("starting Vegeta Console")

		httpOpts := flag.GetHTTPOpts(cmd)
		logging.GetLogger().Info().
			Str("listen", httpOpts.HTTPListen).
			Msg("HTTP options")

		esOpts := flag.GetElasticSearchOpts(cmd)
		logging.GetLogger().Info().
			Strs("urls", esOpts.URLs).
			Str("username", esOpts.Username).
			Msg("ElasticSearch options")

		etcdOpts := flag.GetEtcdOpts(cmd)
		logging.GetLogger().Info().
			Strs("endpoints", etcdOpts.Endpoints).
			Str("username", etcdOpts.Username).
			Msg("etcd options")

		mongoOpts := flag.GetMongoOpts(cmd)
		logging.GetLogger().Info().
			Str("endpoint", mongoOpts.Endpoint).
			Str("username", mongoOpts.Username).
			Msg("Mongo options")

		scannerOpts := flag.GetVegetaScannerOpts(cmd)
		logging.GetLogger().Info().
			Str("host", scannerOpts.Host).
			Int("port", scannerOpts.Port).
			Msg("Vegeta Scanner options")

		console, err := service.NewConsole(httpOpts, esOpts, etcdOpts, mongoOpts, scannerOpts)
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
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")

	flag.AddHTTPFlags(rootCmd)
	flag.AddElasticSearchFlags(rootCmd)
	flag.AddEtcdFlags(rootCmd)
	flag.AddMongoFlags(rootCmd)
	flag.AddVegetaScannerFlags(rootCmd)
}

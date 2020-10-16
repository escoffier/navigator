// Package cmd is for all the Cobra commands
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "scanner",
	Short: "The scanner",
	Long: `The scanner is responsible in doing five things:
1. hash checking of known files
2. malware detection of the executables
3. credential files detection
4. vulnerability static analysis
5. security compliance`,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			logging.SetVerbose()
		}

		httpOpts := flag.GetHTTPOpts(cmd)
		logging.GetLogger().Info().
			Str("listen", httpOpts.HTTPListen).
			Msg("HTTP options")

		mongoOpts := flag.GetMongoOpts(cmd)
		logging.GetLogger().Info().
			Str("endpoint", mongoOpts.Endpoint).
			Str("username", mongoOpts.Username).
			Msg("Mongo options")

		clairOpts := flag.GetClairOpts(cmd)
		logging.GetLogger().Info().
			Str("clair-address", clairOpts.EndpointAddress).
			Int("clair-port", clairOpts.EndpointClairPort).
			Str("clair-remote-address", clairOpts.RemoteClairAddress).
			Int("clair-remote-port", clairOpts.RemoteClairPort).
			Str("clair-ignorefile", clairOpts.IgnoreFileList).
			Str("clair-ignorepackage", clairOpts.IgnorePackageList).
			Str("clair-cvewhite", clairOpts.CVEWhitelist).
			Str("clair-secretpattern", clairOpts.SecretPattern).
			Str("clair-secretpattern", clairOpts.SecretPattern).
			Bool("redclair-skipregistrytlsverify", clairOpts.SkipRegistryTLSVerify).
			Int("redclair-numworkers", clairOpts.NumWorkers).
			Msg("Clair options")

		harborOpts := flag.GetHarborOpts(cmd)
		logging.GetLogger().Info().
			Str("harbor-url", harborOpts.URL).
			Str("harbor-username", harborOpts.Username).
			Str("harbor-password", "***").
			Bool("harbor-skiptlsverify", harborOpts.SkipTLSVerify).
			Msg("Harbor REST client options")

		logging.GetLogger().Info().
			Str("version", Version).
			Msg("starting Vegeta Scanner")

		scanner, err := service.NewScanner(
			httpOpts, mongoOpts, clairOpts, harborOpts)
		if err != nil {
			return err
		}

		lifecycle.NewApplication(
			scanner,
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
	flag.AddMongoFlags(rootCmd)
	flag.AddClairFlags(rootCmd)
	flag.AddHarborFlags(rootCmd)

	flag.ConfigViper()
}

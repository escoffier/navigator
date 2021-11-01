// Package cmd is for all the Cobra commands
package cmd

import (
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service"
	"os"

	"github.com/spf13/cobra"

	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lifecycle"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "scanner",
	Short: "a cloud native devsecops tool",
	RunE: func(cmd *cobra.Command, args []string) error {

		ScannerRunOpts := flag2.GetScannerOpts(cmd)
		global.ScannerOpts = ScannerRunOpts

		if ScannerRunOpts.LogLevel == "debug" {
			logging.SetVerbose()
		}
		logging.GetLogger().Info().
			Str("version", Version).
			Interface("opts", ScannerRunOpts).
			Msg("starting scanner")

		scanner, err := service.NewScanner(ScannerRunOpts)
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
		logging.GetLogger().Error().Err(err).Msg("Failed to startup")
		os.Exit(1)
	}
}

func init() {
	flag2.AddScannerFlags(rootCmd)
	flag.ConfigViper()
}

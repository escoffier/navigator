// Package cmd is for all the Cobra commands
package cmd

import (
	"gitlab.com/piccolo_su/vegeta/cmd/migrate/component/migrate"
	"os"

	"github.com/spf13/cobra"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var rootCmd = &cobra.Command{
	Use:       "tensor-migrate [<action>(up|down|new)] [flags]\n\nDefault Args: \n ",
	Short:     "Update database",
	Long:      `Update database with version files.`,
	ValidArgs: []string{migrate.ActionUp, migrate.ActionDown, migrate.ActionNew},
	Args:      cobra.OnlyValidArgs,

	Run: func(cmd *cobra.Command, args []string) {
		var action string
		if len(args) > 0 {
			action = args[0]
		} else {
			action = ""
		}
		migrate.RunMigrate(action, cmd)
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
	cobra.OnInitialize(func() {
		if err := migrate.InitConfig(migrate.ConfigFile); err != nil {
			logging.GetLogger().Error().Msgf("load config err %v",err )
			os.Exit(1)
		}
		logging.GetLogger().Info().Msg("config OK" )
	})

	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")
	rootCmd.PersistentFlags().StringVarP(&migrate.ConfigFile, "config", "c", "", "migrate config file ")
	rootCmd.Flags().StringVarP(&migrate.VersionsDir, "versions", "V", "./migration-versions", "version files directory")
	rootCmd.Flags().Bool("force-down", false, "reset dirty state and downgrade the current version")
	rootCmd.Flags().StringP("title", "t", "", "migration title")
}



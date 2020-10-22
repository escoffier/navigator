package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version of the Service
	Version string
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print out the software version",
	Long:  `Print out the software version`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Tensoragent v%s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

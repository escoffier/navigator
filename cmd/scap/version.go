package main

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
		fmt.Printf("Vegeta Scap Console v%s\n", Version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}

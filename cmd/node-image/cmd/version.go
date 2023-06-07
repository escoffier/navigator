package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	Version = "v0.0.1"
)

func NewVersionCmd() *cobra.Command {
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print out the software version",
		Long:  `Print out the software version`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("node image canner version:%s\n", Version)
		},
	}
	return versionCmd
}

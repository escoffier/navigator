package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func NewClusterManagerCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:  "cluster-manager",
		Long: "cluster manager",
		Run: func(cmd *cobra.Command, args []string) {
			verbose, _ := cmd.Flags().GetBool("verbose")
			if verbose {
				logging.SetVerbose()
			}
			server, err := NewServer()
			if err != nil {
				logging.GetLogger().Err(err).Msg("failed to create server")
			}

			err = server.Run()
			if err != nil {
				logging.GetLogger().Err(err).Msg("error occurred when server running")
				return
			}
		},
	}
	cmd.AddCommand(versionCmd)
	AddFlags(cmd.Flags())
	return cmd
}

package cmd

import (
	"github.com/spf13/cobra"
	"gitlab.com/security-rd/go-pkg/logging"
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
				logging.Get().Err(err).Msg("failed to create server")
				return
			}

			err = server.Run()
			if err != nil {
				logging.Get().Err(err).Msg("error occurred when server running")
				return
			}
		},
	}
	cmd.AddCommand(versionCmd)
	cmd.PersistentFlags().BoolP("verbose", "v", false, "verbose mode")
	AddFlags(cmd.Flags(), cmd)
	return cmd
}

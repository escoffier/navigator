package cmd

import (
	"github.com/sirupsen/logrus"
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
				logrus.Errorf("failed to create server %v", err)
			}

			err = server.Run()
			if err != nil {
				logrus.Errorf("error occoured when server running %v", err)
				return
			}
		},
	}
	cmd.AddCommand(versionCmd)
	AddFlags(cmd.Flags())
	return cmd
}

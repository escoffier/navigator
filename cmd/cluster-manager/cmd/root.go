package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func NewClusterManagerCommand() *cobra.Command {

	server := NewServer()
	cmd := &cobra.Command{
		Use:  "cluster-manager",
		Long: "cluster manager",
		Run: func(cmd *cobra.Command, args []string) {
			verbose, _ := cmd.Flags().GetBool("verbose")
			if verbose {
				logging.SetVerbose()
			}
			err := server.Init()
			if err != nil {
				logrus.Errorf("failed to init server: %v", err)
				return
			}
			err = server.Run()
			if err != nil {
				logrus.Errorf("error occoured when server running %v", err)
				return
			}
		},
	}
	cmd.AddCommand(versionCmd)
	server.AddFlags(cmd.Flags())
	return cmd
}

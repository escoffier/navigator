package main

import (
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/cmd"
	"os"
)

func main() {
	command := cmd.NewClusterManagerCommand()

	if command.Execute() != nil {
		os.Exit(1)
	}
}

func init() {
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

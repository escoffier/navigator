package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/cmd"
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

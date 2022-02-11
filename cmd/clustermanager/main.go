package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/cmd"
	_ "go.uber.org/automaxprocs"
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

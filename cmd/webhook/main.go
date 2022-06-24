package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/cmd"
	_ "go.uber.org/automaxprocs"
)

func main() {
	command := cmd.NewWebhookCommand()

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

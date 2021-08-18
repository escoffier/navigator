package main

import (
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/cmd"
	"os"
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

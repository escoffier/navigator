package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/image-validate/cmd"
	_ "go.uber.org/automaxprocs"
)

func main() {
	//flag.Parse()
	command := cmd.NewWebhookCommand()

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}

	//config := &webhook.Config{
	//	CertFile: "config/tls.cert",
	//	KeyFile:  "config/tls.key",
	//	Address:  ":9443",
	//}
	//server, err := webhook.NewWebHookServer(config)
	//if err != nil {
	//	log.Errorf("failed to create webhook server : %v", err)
	//	return
	//}
	//
	//// start inject server in new routine
	//go server.Start()
	//log.Info("Server started")

	//signalChan := make(chan os.Signal, 1)
	//signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	//<-signalChan
	//
	//server.Stop()
}

func init() {
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

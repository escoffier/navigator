package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/cmd/seccomp-generator-webhook/mutation"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func main() {
	port := 8080
	certFile := "/etc/webhook/certs/cert.pem"
	keyFile := "/etc/webhook/certs/key.pem"

	cmd := &cobra.Command{
		Use:  "seccomp-generator-webhook",
		Long: "seccomp-generator-webhook",
		Run: func(cmd *cobra.Command, args []string) {
			server := gin.New()

			mutation.RegisterMutateWebhook(server)

			go func() {
				defer func() {
					if r := recover(); r != nil {
						logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
					}
				}()

				address := fmt.Sprintf("0.0.0.0:%d", port)
				if err := http.ListenAndServeTLS(address, certFile, keyFile, server); err != nil {
					panic(err.Error())
				}
			}()

			// listening OS shutdown singal
			signalChan := make(chan os.Signal, 1)
			signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
			<-signalChan

			logrus.Info("received OS shutdown signal, shutting down webhook server gracefully...")
		},
	}

	flags := cmd.Flags()
	flags.IntVar(&port, "port", port, "(optional) the port to bind to")
	flags.StringVar(&certFile, "cert", certFile, "(optional) file containing the x509 Certificate for HTTPS")
	flags.StringVar(&keyFile, "key", keyFile, "(optional) file containing the x509 private key to --cert")

	if err := cmd.Execute(); err != nil {
		panic(err.Error())
	}
}

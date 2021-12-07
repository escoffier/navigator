package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-webhook/config"
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-webhook/mutation"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

func main() {
	preset := "preset.yaml"
	failureRetryInterval := time.Second * 30
	reloadInterval := time.Minute
	port := 8080
	certFile := "/etc/webhook/certs/cert.pem"
	keyFile := "/etc/webhook/certs/key.pem"
	// var dbConnectionString string
	var secProfManagerEndpoint string

	var c *rest.Config
	c, err := rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get in-cluster config")
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(c)

	cmd := &cobra.Command{
		Use:  "seccomp-generator-webhook",
		Long: "seccomp-generator-webhook",
		Run: func(cmd *cobra.Command, args []string) {
			holder, err := config.NewReloadingConfig(preset, &config.ReloadConfig{
				FailureRetryInterval: failureRetryInterval,
				ReloadInterval:       reloadInterval,
			})
			if err != nil {
				panic(err.Error())
			}

			rdbUser := os.Getenv("RDB_USER")
			rdbPassword := os.Getenv("RDB_PASSWORD")
			rdbHost := os.Getenv("RDB_HOST")
			rdbPort := os.Getenv("RDB_PORT")
			rdbDBName := os.Getenv("RDB_DBNAME")
			rdbSSLMode := os.Getenv("RDB_SSLMODE")
			if rdbUser == "" || rdbPassword == "" || rdbHost == "" || rdbPort == "" || rdbSSLMode == "" || rdbDBName == "" {
				logging.GetLogger().Error().Msg("RDB_* env variables are not set")
				return
			}
			pgDSN := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", rdbUser, rdbPassword, rdbHost, rdbPort, rdbDBName, rdbSSLMode)

			db, err := rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
				db, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard.LogMode(logger.Silent)})
				if err != nil {
					logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
					return nil, err
				}
				sqlDB, err := db.DB()
				if err == nil {
					sqlDB.SetMaxOpenConns(30)
					sqlDB.SetMaxIdleConns(5)
					sqlDB.SetConnMaxLifetime(time.Hour)
				}
				return db, nil
			})
			if err != nil {
				logging.GetLogger().Err(err).Msg("Init postgre error")
				panic(err)
			}

			server := gin.New()

			mutation.RegisterMutateWebhook(server, holder, clientset, db, secProfManagerEndpoint)

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
	flags.StringVar(&preset, "preset", preset, "(optional) path to the file container cluster presets")
	flags.IntVar(&port, "port", port, "(optional) the port to bind to")
	flags.DurationVar(&failureRetryInterval, "retry-interval", failureRetryInterval, "(optional) specify the duration between reloads on failure")
	flags.DurationVar(&reloadInterval, "reload-interval", reloadInterval, "(optional) specify the duration between reloads on success")
	flags.StringVar(&certFile, "cert", certFile, "(optional) file containing the x509 Certificate for HTTPS")
	flags.StringVar(&keyFile, "key", keyFile, "(optional) file containing the x509 private key to --cert")

	if err := cmd.Execute(); err != nil {
		panic(err.Error())
	}
}

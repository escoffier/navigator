package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/api"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var port = flag.Int("port", 80, "http port")

func main() {
	router := gin.Default()
	api.InitRouter(router)

	srv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", *port),
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.GetLogger().Fatal().Err(err).Msg("start server failed")
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logging.GetLogger().Fatal().Err(err).Msg("start shutdown failed")
	}
	// catching ctx.Done(). timeout of 5 seconds.
	select {
	case <-ctx.Done():
		logging.GetLogger().Info().Msg("start shutdown success")
	}
	logging.GetLogger().Info().Msg("Server exiting")
}

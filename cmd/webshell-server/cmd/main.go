package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/webshell-server/api"
)

var (
	port           = pflag.Int("port", 80, "http port")
	debug          = pflag.Bool("debug", false, "debug mode")
	loggingOptions *logging.Options
)

func init() {
	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(pflag.CommandLine)
}

func main() {
	pflag.Parse()

	if errs := loggingOptions.Validate(); len(errs) > 0 {
		logging.Get().Panic().Err(fmt.Errorf("%v", errs)).Msg("")
	}

	// 建议移除debug
	// 使用log-level调节日志输出等级
	if *debug {
		loggingOptions.Level = int(zerolog.DebugLevel)
		logging.Get().Warn().Msg("start with DEBUG mode. DONT use in release.")
	}

	loggingOptions.SetConsoleWriterWrapper(logging.ConsoleCallerWriter)
	logging.ReplaceLogger(loggingOptions)

	router := gin.Default()
	api.InitRouter(router)

	srv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", *port),
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Get().Fatal().Err(err).Msg("start server failed")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logging.Get().Fatal().Err(err).Msg("start shutdown failed")
	}
	// catching ctx.Done(). timeout of 5 seconds.
	<-ctx.Done()
	logging.Get().Info().Msg("start shutdown success")
	logging.Get().Info().Msg("Server exiting")
}

package redclair

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
)

func (r *Redclair) StartImageHTTPServer() error {
	rootDir, err := r.CreateHTTPRootDir()
	if err != nil {
		return err
	}

	r.httpRootDir = rootDir

	r.server = r.httpFileServer(rootDir, r.externalPort)
	return nil
}

func (r *Redclair) StopImageHTTPServer() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.server.Shutdown(ctx); err != nil {
		logging.Get().Error().
			Err(err).
			Msg("error in shutting down HTTP server")
		return err
	}
	return nil
}

// TODO if port can't be opened is not handled
func (r *Redclair) httpFileServer(path string, port int) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(path)))
	server := &http.Server{
		// listen on all IPs
		Addr:    fmt.Sprintf("0.0.0.0:%d", port),
		Handler: mux,
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		if err := server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				logging.Get().Err(err).Msg("error in http.Server.ListenAndServe")
			}
		}
	}()
	// It takes some time to open the port, just to be sure we wait a bit
	time.Sleep(100 * time.Millisecond)
	logging.Get().Info().Msgf("Server listening on port %d", port)
	return server
}

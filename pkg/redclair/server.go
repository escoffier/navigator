package redclair

import (
	"fmt"
	"net/http"
	"time"
)

// HTTPFileServer servers files from a specified folder
// TODO if port can't be opened is not handled
func HTTPFileServer(path string, port int) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(path)))
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Error().
					Err(err).
					Msg("error in http.Server.ListenAndServe")
			}
		}
	}()
	// It takes some time to open the port, just to be sure we wait a bit
	time.Sleep(100 * time.Millisecond)
	log.Info().Msgf("[Scanner] Server listening on port %d", port)
	return server
}

package lifecycle

import (
	"os"
	"os/signal"
	"syscall"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// ListenToSignals returns a done channel for capturing syscalls to quit the service
func ListenToSignals() chan struct{} {
	sigs := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigs,
		syscall.SIGABRT, syscall.SIGILL, syscall.SIGINT, syscall.SIGTERM, syscall.SIGSEGV)
	go func() {
		sig := <-sigs
		logging.GetLogger().Info().
			Str("signal", sig.String()).
			Msg("signal caught")
		close(done)
	}()
	return done
}

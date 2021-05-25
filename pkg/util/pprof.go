package util

import (
	"net/http"
	_ "net/http/pprof"
	"os"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	EnvPprofName = "TENSORSEC_PPROF_PORT"
)

func InitPprofMontitor() error {
	env := os.Getenv(EnvPprofName)
	if len(env) == 0 {
		return nil
	}
	addr := ":" + env
	go func() {
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Listen for pprof error")

		}
	}()

	return nil
}

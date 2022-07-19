package degrade

import (
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"

	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	driftPath = "/host/tmp"
)

func driftRecover() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("recover panic: %v", r)
		}
	}()

	finfo, err := os.Stat(fmt.Sprintf("%s/ld.so.preload", driftPath))
	if err != nil {
		logging.Get().Err(err).Msg("drift degrade: error stat or file is not empty")
		return
	}
	if finfo.Size() > 0 {
		return
	}

	rinfo, err := os.Stat(fmt.Sprintf("%s/ld.so.preload.recover", driftPath))
	if err != nil || rinfo.Size() == 0 {
		logging.Get().Err(err).Msg("drift degrade: error stat or recover file is  empty")

		err = os.WriteFile(fmt.Sprintf("%s/ld.so.preload.recover", driftPath), []byte("/.tensor/dp.so"), finfo.Mode())
		if err != nil {
			logging.Get().Err(err).Msg("drift degrade: error write file")
			return
		}
	}

	input, err := os.ReadFile(fmt.Sprintf("%s/ld.so.preload.recover", driftPath))
	if err != nil {
		logging.Get().Err(err).Msg("drift degrade: error read recover file")
		return
	}

	err = os.WriteFile(fmt.Sprintf("%s/ld.so.preload", driftPath), input, finfo.Mode())
	if err != nil {
		logging.Get().Err(err).Msg("drift degrade: error write file")
		return
	}
	if err := os.Remove(fmt.Sprintf("%s/ld.so.preload.recover", driftPath)); err != nil {
		logging.Get().Warn().Err(err).Msg("remove recover file error")
	}

	logging.Get().Info().Msg("Recovery for drift defense is done")
}
func driftDegrade() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("degrade panic: %v", r)
		}
	}()

	finfo, err := os.Stat(fmt.Sprintf("%s/ld.so.preload", driftPath))
	if err != nil {
		logging.Get().Err(err).Msg("drift degrade: error stat or file is empty")
		return
	}
	if finfo.Size() == 0 {
		return
	}
	if err := os.Remove(fmt.Sprintf("%s/ld.so.preload.recover", driftPath)); err != nil {
		logging.Get().Warn().Err(err).Msg("remove recover file error")
	}

	input, err := os.ReadFile(fmt.Sprintf("%s/ld.so.preload", driftPath))
	if err != nil {
		logging.Get().Err(err).Msg("drift degrade: error read file")
		return
	}

	err = os.WriteFile(fmt.Sprintf("%s/ld.so.preload.recover", driftPath), input, finfo.Mode())
	if err != nil {
		logging.Get().Err(err).Msg("drift degrade: error write file")
		return
	}

	err = exec.Command("/bin/bash", "-c", fmt.Sprintf("echo -n > %s", fmt.Sprintf("%s/ld.so.preload", driftPath))).Run()
	// err = os.Truncate(fmt.Sprintf("%s/ld.so.preload", driftPath), 0)
	if err != nil {
		logging.Get().Err(err).Msg("drift degrade: error empty file")
		return
	}
	logging.Get().Info().Msg("Degradion for drift defense is done")
}

package cmd

import (
	"bytes"
	"os/exec"

	"github.com/rs/zerolog/log"
)

func RunCmd(cmd string, args ...string) (bytes.Buffer, bytes.Buffer, error) {
	osCmd := exec.Command(cmd, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	osCmd.Stdout = &out
	osCmd.Stderr = &stderr

	log.Debug().Msgf("%v", osCmd.Args)

	return out, stderr, osCmd.Run()
}

package util

import (
	"bytes"
	"os/exec"
)

func ExecuteCmd(cmd *exec.Cmd) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	var err = cmd.Run()
	return stdout.String(), stderr.String(), err
}

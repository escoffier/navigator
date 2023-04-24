package execcmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var NewCmdFunc func(name string, arg ...string) *exec.Cmd

func init() {
	NewCmdFunc = exec.Command
}

func RunCommandWithEnv(command string, envs []string) (output string, err error) {

	command = strings.TrimSpace(command)
	if len(command) == 0 {
		return output, err
	}

	cmd := NewCmdFunc("sh")

	cmd.Stdin = strings.NewReader(command)
	if len(envs) > 0 {
		logging.GetLogger().Info().Strs("envs", envs).Msg("Command envs")
		cmd.Env = append(os.Environ(), envs...)
	}
	out, err := cmd.CombinedOutput()
	output = string(out)
	if err != nil && err.Error() != "exit status 1" {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", command, output, err)
	} else {
		if err != nil {
			logging.GetLogger().Warn().Msgf("Command return error: %s", err.Error())
			err = nil
		}
		logging.GetLogger().Info().Str("command", command).Str("output", output).Msg("Command executed")
	}
	return output, err
}

func RunCommandWithOutputAndEnvs(command string, envs []string) (output string, err error) {
	command = strings.TrimSpace(command)
	if len(command) == 0 {
		return output, err
	}

	cmd := NewCmdFunc("sh")
	cmd.Stdin = strings.NewReader(command)
	if len(envs) > 0 {
		cmd.Env = append(os.Environ(), envs...)
	}

	out, err := cmd.Output()
	output = string(out)

	if err != nil {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", command, output, err)
	} else {
		logging.GetLogger().Info().Str("command", command).Str("output", output).Msg("Command executed")
	}

	return output, err
}

func RunCommand(command string) (output string, err error) {
	command = strings.TrimSpace(command)
	if len(command) == 0 {
		return output, err
	}

	cmd := NewCmdFunc("sh")
	cmd.Stdin = strings.NewReader(command)

	out, err := cmd.CombinedOutput()
	output = string(out)

	if err != nil && err.Error() != "exit status 1" {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", command, output, err)
	} else {
		if err != nil {
			logging.GetLogger().Warn().Msgf("Command return error: %s", err.Error())
			err = nil
		}
		logging.GetLogger().Info().Str("command", command).Str("output", output).Msg("Command executed")
	}

	return output, err
}

func RunCommandWithOutput(command string) (output string, err error) {
	command = strings.TrimSpace(command)
	if len(command) == 0 {
		return output, err
	}

	cmd := NewCmdFunc("sh")
	cmd.Stdin = strings.NewReader(command)

	out, err := cmd.Output()
	output = string(out)

	if err != nil {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", command, output, err)
	} else {
		logging.GetLogger().Info().Str("command", command).Str("output", output).Msg("Command executed")
	}

	return output, err
}

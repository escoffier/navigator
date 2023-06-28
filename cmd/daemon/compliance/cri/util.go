package cri

import (
	"fmt"
	"os/exec"
	"strings"

	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/logging"
)

var nc check.NewCommand

func init() {
	nc = func() *exec.Cmd { return exec.Command("sh") }
}

type Platform struct {
	Name    string
	Version string
}

func (p Platform) String() string {
	return fmt.Sprintf("%s-%s", p.Name, p.Version)
}

func getPlatformInfo() Platform {
	dockerVersion, err := getDockerVersion()
	if err != nil {
		logging.Get().Warn().Msgf("Version check failed: %s\nAlternatively, you can specify the version with --version", err)
		return Platform{}
	}

	return Platform{
		Name:    "docker",
		Version: dockerVersion,
	}
}

// getDockerVersion returns the docker server engine version.
func getDockerVersion() (string, error) {
	res, err := check.RunCommandWithOutput(nc, "docker version -f {{.Server.Version}}")
	return strings.TrimSpace(res), err
}

func getDockerSwarm() (platform string, err error) {
	res, err := check.RunCommandWithOutput(nc, "docker info | grep Swarm")
	if err != nil || strings.Contains(res, "inactive") {
		return "inactive", err
	}
	return "active", nil
}

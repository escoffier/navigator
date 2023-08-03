package cri

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
	RuntimeCriO       = "cri-o"
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
		logging.Get().Info().Msgf("Version check failed: %s\nAlternatively, you can specify the version with --version", err)
	} else {
		return Platform{
			Name:    RuntimeDocker,
			Version: dockerVersion,
		}
	}

	crioVersion, err := getCrioVersion()
	if err != nil {
		logging.Get().Info().Err(err).Msg("getCrioVersion error")
	} else {
		return Platform{
			Name:    RuntimeCriO,
			Version: crioVersion,
		}
	}

	containerdVersion, err := getContainerdVersion()
	if err != nil {
		logging.Get().Info().Err(err).Msg("getContainerdVersion error")
	} else {
		return Platform{
			Name:    RuntimeContainerd,
			Version: containerdVersion,
		}
	}

	// 如果没有判断到container runtime环境，默认为docker
	return Platform{
		Name:    RuntimeDocker,
		Version: "18.09",
	}
}

type CrioVersionResp struct {
	Version      string    `json:"version"`
	GitCommit    string    `json:"gitCommit"`
	GitTreeState string    `json:"gitTreeState"`
	BuildDate    time.Time `json:"buildDate"`
	GoVersion    string    `json:"goVersion"`
	Compiler     string    `json:"compiler"`
	Platform     string    `json:"platform"`
	Linkmode     string    `json:"linkmode"`
}

func getCrioVersion() (string, error) {
	res, err := check.RunCommandWithOutput(nc, "crio version -j")
	if err != nil {
		return "", err
	}

	logging.Get().Info().Msg(res)

	ver := CrioVersionResp{}
	err = json.Unmarshal([]byte(res), &ver)
	return ver.Version, err
}

func getContainerdVersion() (string, error) {
	res, err := check.RunCommandWithOutput(nc, "nerdctl version -f '{{(index .Server.Components 0).Version}}'")
	if err == nil {
		return strings.TrimSpace(res), nil
	}

	logging.Get().Info().Err(err).Msg(res)

	res, err = check.RunCommandWithOutput(nc, "ctr -v")
	if err != nil {
		return "", err
	}

	// res
	// eg: ctr containerd.io 1.6.21
	logging.Get().Info().Msgf("ctr -v response: %s", res)

	if vs := strings.Split(res, " "); len(vs) > 0 {
		return vs[len(vs)-1], nil
	}

	return "0.0.1", nil
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

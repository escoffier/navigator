package container

import (
	"os"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"
)

func isUnixSockFile(filename string) bool {
	if strings.HasPrefix(filename, "unix://") {
		filename = filename[len("unix://"):]
	}

	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeSocket) != 0
}

func CreateRuntimeCli() (Runtime, error) {
	var rt Runtime
	var err error
	dockerHost := os.Getenv("DOCKER_SOCKET_ADDR")
	if dockerHost == "" {
		dockerHost = defaultDockerSocket
	}
	if isUnixSockFile(dockerHost) {
		rt, err = Open(RuntimeConfig{Type: "docker"})
		if err != nil {
			logging.Get().Err(err).Str("runtimeType", "docker").Msg("Open runtime")
			return nil, err
		}
	} else {
		rt, err = Open(RuntimeConfig{Type: "containerd"})
		if err != nil {
			logging.Get().Err(err).Str("runtimeType", "containerd").Msg("Open runtime")
			return nil, err
		}
	}
	return rt, nil
}

package container

import (
	"fmt"
	"os"
	"strings"
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
			return nil, err
		}
	} else {
		// todo: support containerd or cri-o unix socket
		return nil, fmt.Errorf("not valid runtime socket")
	}
	return rt, nil
}

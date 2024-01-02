package container

import (
	"fmt"
	"os"
	"strings"
)

func IsUnixSockFile(filename string) error {
	if strings.HasPrefix(filename, "unix://") {
		filename = filename[len("unix://"):]
	}

	info, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("not find sockerfile:%s", filename)
	}
	if (info.Mode() & os.ModeSocket) == 0 {
		return fmt.Errorf("not docker file:%s", filename)
	}
	return nil
}

func CreateRuntimeCli() (Runtime, error) {
	if rt, err := Open(RuntimeConfig{Type: "docker"}); err == nil {
		return rt, nil
	}

	if rt, err := Open(RuntimeConfig{Type: "containerd"}); err == nil {
		return rt, nil
	}

	if rt, err := Open(RuntimeConfig{Type: "crio"}); err == nil {
		return rt, nil
	}

	return nil, fmt.Errorf("not support cri type")
}

package global

import (
	"github.com/docker/docker/api/types"
	"os"
	"path/filepath"
)

func GetDpRealWorkingDir() string {
	mode := os.Getenv(DaemonRunModeEnv)
	if mode == DaemonRunModeLocal {
		return WorkingDir
	}
	return filepath.Join(MountPathInContainer, WorkingDir)
}

// RuntimeDataDir return data dir,eg./var/lib/docker
func RuntimeDataDir(runtime types.Info) string {
	mode := os.Getenv(DaemonRunModeEnv)
	if mode == DaemonRunModeLocal {
		return runtime.DockerRootDir
	}
	return filepath.Join(MountPathInContainer, runtime.DockerRootDir)
}

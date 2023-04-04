package global

import (
	"github.com/docker/docker/api/types"
	"os"
	"path/filepath"
	"strings"
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

func GetExcludeNamespaces() []string {
	// default exclude ns
	namespaces := []string{
		"kube-system",
		"kube-public",
		"kube-node-lease",
		"kube-node-lease-renewer",
		"kube-node-lease-maintenance",
		"kube-node-lease-reclaim",
		"kube-node-lease-preemptor",
		"kube-node-lease-preemptor-maintenance",
		"kube-node-lease-preemptor-renewer",
		"kube-node-lease-preemptor-reclaim",
	}

	// custom exclude ns by env
	excludeNamespacesEnv := os.Getenv("EXCLUDE_NAMESPACES")
	if excludeNamespacesEnv != "" {
		tmpNamespaces := strings.Split(excludeNamespacesEnv, ":")
		namespaces = append(namespaces, tmpNamespaces...)
	}

	return namespaces
}

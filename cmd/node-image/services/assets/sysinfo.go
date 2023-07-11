package assets

import (
	"os"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
)

type SysInfo struct {
	HostName   string
	HostIP     string
	ClusterKey string
}

func GetNodeSysInfo() *SysInfo {
	s := &SysInfo{}

	// get node name
	hostName := os.Getenv("MY_NODE_NAME")
	if hostName == "" {
		hostName = "Unknown"
	}
	s.HostName = hostName

	// node ip
	hostIP := os.Getenv("MY_HOST_IP")
	if hostIP == "" {
		hostIP = "Unknown"
	}
	s.HostIP = hostIP

	// get cluster key
	clusterAddr := os.Getenv("CLUSTER_MANAGER_URL")
	if clusterAddr == "" {
		logging.Get().Error().Msg("env CLUSTER_MANAGER_URL not found")
		return s
	}
	clusterManager := k8s.NewClusterInfoManager(clusterAddr)
	clusterKey, ok := clusterManager.ClusterKey()
	if !ok {
		logging.Get().Error().Msg("get cluster key failed")
		return s
	}
	s.ClusterKey = clusterKey

	return s
}

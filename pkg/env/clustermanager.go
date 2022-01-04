package env

import "gitlab.com/piccolo_su/vegeta/pkg/util"

const (
	clusterManagerUrl        = "CLUSTER_MANAGER_URL"
	defaultClusterManagerUrl = "http://cluster-manager:9443"
)

func GetClusterManagerUrl() string {
	return util.GetEnvWithDefault(clusterManagerUrl, defaultClusterManagerUrl)
}

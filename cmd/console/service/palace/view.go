package palace

type TreeNode struct {
	ClusterKey    string      `json:"clusterKey"`
	Namespace     string      `json:"namespace"`
	PodName       string      `json:"podName"`
	ContainerName string      `json:"containerName"`
	PID           int64       `json:"pid"`
	Pname         string      `json:"pname"`
	Children      []*TreeNode `json:"children"`
}

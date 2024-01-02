package api

// 中移定制化的需求
type ImageAssets struct {
	Args              []string          `json:"args"`
	ClusterName       string            `json:"clusterName"`
	ContainerFullName string            `json:"containerFullName"`
	ContainerHashID   string            `json:"containerHashID"`
	ContainerName     string            `json:"containerName"`
	ContainerRunState int64             `json:"containerRunState"`
	ContainerType     []string          `json:"containerType"`
	NodeHostname      string            `json:"nodeHostname"`
	NodeIP            string            `json:"nodeIP"`
	PodName           string            `json:"podName"`
	PodNamespace      string            `json:"podNamespace"`
	Labels            map[string]string `json:"labels"`
	PodStartAt        int64             `json:"podStartAt"` // 毫秒时间戳
	PodStopAt         int64             `json:"podStopAt"`  // 毫秒时间戳
	ImageHasVuln      bool              `json:"imageHasVuln"`
	ImageHost         string            `json:"imageHost"`
	ImageRepo         string            `json:"imageRepo"`
	ImageDigest       string            `json:"imageDigest"` // digest
	ImageTag          string            `json:"imageTag"`
}

package clusterserver

const (
	HostClusterName = "default"
)

type TensorCluster struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int32  `json:"status"`
	ConsoleUrl  string `json:"console_url"`
}

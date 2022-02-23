package clusterserver

import "gitlab.com/piccolo_su/vegeta/pkg/k8s"

const (
	HostClusterName = "default"
)

type TensorCluster struct {
	Key           string                    `json:"key"`
	Name          string                    `json:"name"`
	Description   string                    `json:"description"`
	Status        int32                     `json:"status"`
	ConsoleUrl    string                    `json:"console_url"`
	K8SRestConfig *k8s.K8SInfoForRestConfig `json:"k8s_rest_config"`
}

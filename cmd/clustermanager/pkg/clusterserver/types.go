package clusterserver

import "gitlab.com/piccolo_su/vegeta/pkg/k8s"

type TensorCluster struct {
	Key           string                 `json:"key"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Status        int32                  `json:"status"`
	ConsoleURL    string                 `json:"console_url"`
	K8SRestConfig *k8s.InfoForRestConfig `json:"k8s_rest_config"`
}

type TensorPod struct {
	ClusterKey string `json:"clusterKey"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

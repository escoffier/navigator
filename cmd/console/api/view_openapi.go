package api

import (
	corev1 "k8s.io/api/core/v1"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type PodResourceRelationOpenApi struct {
	ClusterKey   string `json:"clusterKey"`
	PodIP        string `json:"podIP"`
	PodUID       string `json:"podUID"`
	HostIP       string `json:"hostIP"`
	Namespace    string `json:"namespace"`
	PodName      string `json:"podName"`
	NodeName     string `json:"nodeName"`
	ResourceName string `json:"resourceName"`
	ResourceKind string `json:"resourceKind"`

	CreatedAt int64 `json:"createdAt"`
	UpdatedAt int64 `json:"updatedAt"`
}

type TensorNamespaceOpenApi struct {
	Name       string
	ClusterKey string
	Alias      string
	Authority  string
}
type ContainerOpenApi struct {
	ClusterKey   string `json:"clusterKey"`
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	ResourceKind string `json:"resourceKind"`
	ResourceName string `json:"resourceName"`
	Image        string `json:"image"`
}

type resourceContainerOpenApi struct {
	Image         string `json:"image"`
	Namespace     string `json:"namespace"`
	ContainerName string `json:"containerName"`
	ResourceName  string `json:"resourceName"`
	ClusterKey    string `json:"clusterKey"`
	ResourceKind  string `json:"resourceKind"`
}

type TensorNodeOpenApi struct {
	ClusterKey              string                  `json:"clusterKey"`
	HostName                string                  `json:"hostName"`
	NodeIP                  string                  `json:"nodeIP"`
	KernelVersion           string                  `json:"kernelVersion"`
	OsInfo                  string                  `json:"osInfo"`
	OsImage                 string                  `json:"osImage"`
	ContainerRuntimeVersion string                  `json:"containerRuntimeVersion"`
	KubeletVersion          string                  `json:"kubeletVersion"`
	KubeProxyVersion        string                  `json:"kubeProxyVersion"`
	Architecture            string                  `json:"architecture"`
	Volumes                 []NodeVolume            `json:"volumes"`
	ContainerImages         []corev1.ContainerImage `json:"containerImages"`
	CreatedAt               int64                   `json:"createdAt"`
	UpdatedAt               int64                   `json:"updatedAt"`
	Status                  int8                    `json:"status"`
}
type NodeVolume struct {
	Type       string `json:"type"`
	VolumeName string `json:"volumeName"`
	DevicePath string `json:"devicePath"`
}

type TensorResourceOpenApi struct {
	Alias        string   `json:"alias"`
	ResourceName string   `json:"resourceName"`
	Namespace    string   `json:"namespace"`
	ClusterKey   string   `json:"clusterKey"`
	UID          string   `json:"uid"`
	ResourceKind string   `json:"resourceKind"`
	Managers     []string `json:"managers"`
	Authority    string   `json:"authority"`

	CreatedAt int64 `json:"createdAt"`
	UpdatedAt int64 `json:"updatedAt"`
}

type ResourceContainerOpenApi struct {
	Image         string               `json:"image"`
	Namespace     string               `json:"namespace"`
	ContainerName string               `json:"containerName"`
	ResourceName  string               `json:"resourceName"`
	ClusterKey    string               `json:"clusterKey"`
	ClusterName   string               `json:"clusterName"`
	ResourceKind  string               `json:"resourceKind"`
	Ports         model.ContainerPorts `json:"ports"`
	WorkingDir    string               `json:"workingDir"`
	Command       []string             `json:"command"`
}

type ResourceSummery struct {
	NamespacesNum int64 `json:"namespacesNum"`
	ResourcesNum  int64 `json:"resourcesNum"`
	NodeNum       int64 `json:"nodeNum"`
	PodNum        int64 `json:"podNum"`
	ContainerNum  int64 `json:"containerNum"`
}

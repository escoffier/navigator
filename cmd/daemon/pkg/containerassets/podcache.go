package containerassets

import corev1 "k8s.io/api/core/v1"

type PodCache interface {
	GetPodOwner(namespace, name string) (string, string, error)
	GetPod(namespace, name string) (*corev1.Pod, error)
}

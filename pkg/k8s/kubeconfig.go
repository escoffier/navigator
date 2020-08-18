// Package k8s has the convenient methods for kubernetes
package k8s

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// CreateK8sClientFromKubeConfig creates kubernetes.Clientset from kubeconfig byte array
func CreateK8sClientFromKubeConfig(kubeconfig []byte) (*kubernetes.Clientset, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}

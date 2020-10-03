// Package k8s has the convenient methods for kubernetes
package k8s

import (
	b64 "encoding/base64"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	nameSpace = "vegeta"
)

// CreateK8sClientFromKubeConfig creates kubernetes.Clientset from kubeconfig byte array
func CreateK8sClientFromKubeConfig(kubeconfig []byte) (*kubernetes.Clientset, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}

func KubeClientFromB64KubeConfig(kubeConfig string) (*kubernetes.Clientset, error) {
	kubeconfig, err := b64.StdEncoding.DecodeString(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Can't decode kubeconfig: %s", err)
	}

	kubeClient, err := CreateK8sClientFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Cluster API Request: %s", err)
	}
	return kubeClient, nil
}

func CheckKubeClientConnection(kubeClient *kubernetes.Clientset) error {
	_, err := kubeClient.CoreV1().Namespaces().Get(nameSpace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Maybe namespace doesn't exist or no authorization?: %s", err)
	}
	_, err = kubeClient.CoreV1().Pods(nameSpace).List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Maybe no pod view authorization?: %s", err)
	}
	return nil
}

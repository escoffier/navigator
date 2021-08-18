// Package k8s has the convenient methods for kubernetes
package k8s

import (
	b64 "encoding/base64"
	"fmt"
	"os"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

func GetRestConfigFromKubeConfig(kubeConfig string) (*rest.Config, error) {
	kubeconfig, err := b64.StdEncoding.DecodeString(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Can't decode kubeconfig: %s", err)
	}
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	return config, nil
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
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	_, err := kubeClient.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Maybe namespace doesn't exist or no authorization?: %s", err)
	}
	_, err = kubeClient.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Maybe no pod view authorization?: %s", err)
	}
	return nil
}

func KubeClientFromServiceAccoount() (*kubernetes.Clientset, *rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Info().Msgf("form service account get config error：%+v", err.Error())
		return nil, nil, err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logging.GetLogger().Info().Msgf("form service account get clientset error：%+v", err.Error())
		return nil, nil, err
	}
	return clientset, config, nil
}

// Package k8s has the convenient methods for kubernetes
package k8s

import (
	"context"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"gitlab.com/piccolo_su/vegeta/pkg/model"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
)

type InfoForRestConfig struct {
	CertData      []byte `json:"cert_data"`
	KeyData       []byte `json:"key_data"`
	CAData        []byte `json:"ca_data"`
	Token         []byte `json:"token"`
	APIServerAddr string `json:"apiserver_addr"`
}

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

func CheckKubeClientConnection(ctx context.Context, kubeClient *kubernetes.Clientset) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	_, err := kubeClient.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Maybe namespace doesn't exist or no authorization?: %s", err)
	}
	_, err = kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
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

func CreateK8sClient(cluster *model.TensorCluster) (*kubernetes.Clientset, error) {
	tlsClientConfig := rest.TLSClientConfig{Insecure: false}
	ca := []byte(cluster.CertificateAuthData)
	_, err := certutil.NewPoolFromBytes(ca)
	if err != nil {
		tlsClientConfig.Insecure = true
	} else {
		tlsClientConfig.CAData = ca
	}

	var clientSet *kubernetes.Clientset
	if cluster.SecretToken == "" {
		tlsClientConfig.CertData = []byte(cluster.ClientCertData)
		tlsClientConfig.KeyData = []byte(cluster.ClientKeyData)
	}

	clientSet, err = kubernetes.NewForConfig(&rest.Config{
		Host:            cluster.APIServerAddr,
		TLSClientConfig: tlsClientConfig,
		BearerToken:     cluster.SecretToken,
	})
	if err != nil {
		return nil, err
	}
	return clientSet, nil
}

func GenKubeConfig(c *InfoForRestConfig) (*rest.Config, error) {
	if c == nil {
		return nil, errors.New("invalid config")
	}
	tlsClientConfig := rest.TLSClientConfig{Insecure: false}
	if _, err := certutil.NewPoolFromBytes(c.CAData); err != nil {
		logging.GetLogger().Warn().Msgf("load root CA config err: %v", err)
		tlsClientConfig.Insecure = true
	} else {
		tlsClientConfig.CAData = c.CAData
	}

	if len(c.Token) == 0 {
		if len(c.CertData) == 0 || len(c.KeyData) == 0 {
			return nil, errors.New("invalid cert data")
		}
		tlsClientConfig.CertData = c.CertData
		tlsClientConfig.KeyData = c.KeyData
	}
	return &rest.Config{
		Host:            c.APIServerAddr,
		TLSClientConfig: tlsClientConfig,
		BearerToken:     string(c.Token),
	}, nil
}

//KubeConfig get config from  cluster manager and generate rest.Config
func KubeConfig() (*rest.Config, error) {
	host := os.Getenv("CLUSTER_MANAGER_URL")
	if host == "" {
		return nil, fmt.Errorf("no cluster manager url")
	}

	var cluster *TensorCluster
	stopChan := make(chan struct{})
	err := wait.PollImmediateUntil(12*time.Second, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		logging.GetLogger().Info().Msg("trying to get cluster info from cluster manager")
		var err error
		cluster, err = getK8sClusterInfo(ctx, host)
		if err == nil {
			return true, nil
		}
		return false, nil
	}, stopChan)
	if err != nil {
		return nil, err
	}

	return GenKubeConfig(cluster.K8SRestConfig)
}

func GetTensorCluster() (*TensorCluster, error) {
	host := os.Getenv("CLUSTER_MANAGER_URL")
	if host == "" {
		return nil, fmt.Errorf("no cluster manager url")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cluster, err := getK8sClusterInfo(ctx, host)
	return cluster, err
}

func CreateClientset(cluster *model.TensorCluster) (*assets.Clientset, error) {
	tlsClientConfig := rest.TLSClientConfig{Insecure: false}
	ca := []byte(cluster.CertificateAuthData)
	_, err := certutil.NewPoolFromBytes(ca)
	if err != nil {
		tlsClientConfig.Insecure = true
	} else {
		tlsClientConfig.CAData = ca
	}

	var clientSet *assets.Clientset
	if cluster.SecretToken == "" {
		tlsClientConfig.CertData = []byte(cluster.ClientCertData)
		tlsClientConfig.KeyData = []byte(cluster.ClientKeyData)
	}
	clientSet, err = assets.NewForConfig(&rest.Config{
		Host:            cluster.APIServerAddr,
		TLSClientConfig: tlsClientConfig,
		BearerToken:     cluster.SecretToken,
	})
	if err != nil {
		return nil, err
	}
	return clientSet, nil
}

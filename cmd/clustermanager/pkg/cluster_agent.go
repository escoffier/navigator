package clusteragent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/types"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/k8s"

	"github.com/avast/retry-go"
	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
)

const (
	clusterInfo    = "cluster-info"
	clusterInfoKey = "cluster-info"
)

type SAToken struct {
	Token  []byte
	CaData []byte
}

type CertsData struct {
	keyData  []byte
	certData []byte
	caData   []byte
}

type ClusterAgent struct {
	masterAddr      string
	CusterID        string
	Name            string
	KubeRestConfig  *k8s.InfoForRestConfig
	apiServerAddr   string
	Description     string
	ClusterType     model.ClusterType
	httpClient      *http.Client
	tlsClient       bool
	workerNamespace string
	HostClient      *assets.Clientset
}

const (
	kubeRootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenFile      = "/etc/secrets/cluster-admin/token" //nolint
	rootCAFile     = "/etc/secrets/cluster-admin/ca.crt"
	masterAssetURL = "/internal/platform/assets/cluster"
	tlsCAFile      = "/etc/tensorsec/cluster-manager/tls.crt"
	tlsKeyFile     = "/etc/tensorsec/cluster-manager/tls.key"

	ApiServerCaFile   = "/etc/secrets/cluster-admin/ca.crt"
	ApiServerCertFile = "/etc/secrets/cluster-admin/tls.crt"
	ApiServerKeyFile  = "/etc/secrets/cluster-admin/tls.key"
)

func NewClusterAgent(config *config.Config) *ClusterAgent {
	return &ClusterAgent{
		masterAddr:      config.MasterAddr,
		Name:            config.Name,
		apiServerAddr:   config.APIServerAddr,
		workerNamespace: config.WorkerNamespace,
		ClusterType:     config.ClusterType,
	}
}

func (c *ClusterAgent) getHTTPClient() (*http.Client, error) {
	if c.tlsClient {
		caCert, err := ioutil.ReadFile(tlsCAFile)
		if err != nil {
			logging.Get().Err(err).Msg("open /auth/ca/tls.crr error")
			return nil, err
		}

		clientCertPool := x509.NewCertPool()
		if !clientCertPool.AppendCertsFromPEM(caCert) {
			return nil, err
		}

		cert, err := tls.LoadX509KeyPair(tlsCAFile, tlsKeyFile)
		if err != nil {
			return nil, err
		}
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{ //nolint
					Certificates: []tls.Certificate{cert},
					RootCAs:      clientCertPool,
				},
			},
		}, nil
	} else {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}, nil
	}
}

func (c *ClusterAgent) Init() error {
	client, err := c.getHTTPClient()
	if err != nil {
		return err
	}

	c.httpClient = client

	if c.ClusterType == model.HostCluster {
		clusterConfig, err := rest.InClusterConfig()
		if err != nil {
			return err
		}
		c.apiServerAddr = clusterConfig.Host
	}

	restConfig := &k8s.InfoForRestConfig{
		APIServerAddr: c.apiServerAddr,
	}

	saToken, err := loadSATokenData()
	if err == nil {
		restConfig.CAData = saToken.CaData
		restConfig.Token = saToken.Token
	} else {
		certData, err := loadCertsData()
		if err != nil {
			return err
		} else {
			restConfig.CAData = certData.caData
			restConfig.CertData = certData.certData
			restConfig.KeyData = certData.keyData
		}
	}
	c.KubeRestConfig = restConfig

	kubeConfig, err := k8s.GenKubeConfig(c.KubeRestConfig)
	if err != nil {
		return err
	}
	c.HostClient, err = assets.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	err = c.fetchClusterKey()
	if err != nil {
		return err
	}
	logging.Get().Info().Msgf("cluster id : %s", c.CusterID)
	return nil
}

func (c *ClusterAgent) RegisterToHostCluster() {
	if c.ClusterType == model.MemberCluster {
		stopChan := make(chan struct{})
		err := wait.PollImmediateUntil(time.Second*60, func() (bool, error) {
			err := c.registerClusterInfo()
			if err != nil { //nolint
				return false, nil //nolint
			}
			return true, nil
		}, stopChan)
		if err != nil {
			logging.Get().Err(err).Msg("failed to register host cluster")
			return
		}
		logging.Get().Info().Msg("successfully registered to master cluster")
	}
}

type TensorCluster struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"Description"`
	Status      int32  `json:"status"`
}

func (c *ClusterAgent) registerClusterInfo() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	cluster := &model.TensorCluster{
		Key:                 c.CusterID,
		Name:                c.Name,
		ClusterType:         c.ClusterType,
		Description:         c.Description,
		APIServerAddr:       c.apiServerAddr,
		CertificateAuthData: string(c.KubeRestConfig.CAData),
		SecretToken:         string(c.KubeRestConfig.Token),
		ClientCertData:      string(c.KubeRestConfig.CertData),
		ClientKeyData:       string(c.KubeRestConfig.KeyData),
		WorkerNamespace:     c.workerNamespace,
		Status:              0,
	}

	data, err := json.Marshal(cluster)
	if err != nil {
		logging.Get().Err(err).Msg("Failed to marshal cluster")
		return err
	}
	logging.Get().Info().Msgf("###### cluster: %s", string(data))
	logging.Get().Info().Msgf("register to %s", buildURL(c.masterAddr, masterAssetURL))
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, buildURL(c.masterAddr, masterAssetURL), bytes.NewReader(data))
	if err != nil {
		return err
	}
	respHandler := func(resp *http.Response, err error) error {
		if err != nil {
			logging.Get().Err(err).Msgf("post cluster info err : %v", err)
			return err
		}

		if resp.StatusCode != http.StatusOK {
			logging.Get().Error().Msgf("http resp error: %s", resp.Status)
			return fmt.Errorf("http resp error: %s", resp.Status)
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logging.Get().Debug().Msg(string(data))
		return nil
	}

	logging.Get().Debug().Msgf("post cluster info to master cluster %v", string(data))
	err = util.HTTPRequest(ctx, c.httpClient, request, respHandler, retry.Attempts(3))
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterAgent) updateClusterInfo() {
	type updateCluster struct {
		ClusterKey  string `json:"cluster_key"`
		Name        string `json:"name"`
		Description string `json:"Description"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	req := updateCluster{
		ClusterKey:  c.CusterID,
		Name:        c.Name,
		Description: c.Description,
	}

	data, err := json.Marshal(req)
	if err != nil {
		logging.Get().Err(err).Msg("Failed to marshal cluster")
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, buildURL(c.masterAddr, masterAssetURL), bytes.NewReader(data))
	if err != nil {
		return
	}

	respHandler := func(resp *http.Response, err error) error {
		if err != nil {
			logging.Get().Err(err).Msg("post cluster info err")
			return err
		}

		if resp.StatusCode != http.StatusOK {
			logging.Get().Error().Msgf("http resp error: %s", resp.Status)
			return fmt.Errorf("http resp error: %s", resp.Status)
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logging.Get().Debug().Msg(string(data))
		return nil
	}

	logging.Get().Debug().Msgf("post cluster info to master cluster %s", string(data))
	err = util.HTTPRequest(ctx, c.httpClient, request, respHandler, retry.Attempts(3))
	if err != nil {
		logging.Get().Err(err).Msg("post cluster info to master cluster err")
		return
	}
}

func buildURL(host, path string) string {
	if strings.Contains(host, "http") {
		return host + path
	}
	return "http://" + host + path
}

func loadSATokenData() (*SAToken, error) {
	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	var caData []byte
	if _, err = certutil.NewPool(rootCAFile); err != nil {
		logging.Get().Err(err).Msg("load-file-err")
		return nil, err
	} else {
		caData, err = ioutil.ReadFile(rootCAFile)
		if err != nil {
			return nil, err
		}
	}

	return &SAToken{
		Token:  token,
		CaData: caData,
	}, nil
}

func loadCertsData() (*CertsData, error) {
	certData, err := ioutil.ReadFile(ApiServerCertFile)
	if err != nil {
		return nil, err
	}
	keyData, err := ioutil.ReadFile(ApiServerKeyFile)
	if err != nil {
		return nil, err
	}

	logging.Get().Info().Msgf("cert: %s", string(certData))
	logging.Get().Info().Msgf("key: %s", string(keyData))
	var caData []byte
	var caFile string
	if _, err = certutil.NewPool(ApiServerCaFile); err != nil {
		logging.Get().Err(err).Msg("load custom root ca file err")
		_, err = certutil.NewPool(kubeRootCAFile)
		if err != nil {
			logging.Get().Err(err).Msg("load kube default root ca file err")
			return nil, err
		}
		caFile = kubeRootCAFile
	} else {
		caFile = ApiServerCaFile
	}
	caData, err = ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	logging.Get().Info().Msgf("ca: %s", string(caData))
	return &CertsData{
		keyData:  keyData,
		certData: certData,
		caData:   caData,
	}, nil
}

func (c *ClusterAgent) fetchClusterKey() error {
	var err error
	cm, err := c.HostClient.CoreV1().ConfigMaps(c.workerNamespace).Get(context.TODO(), clusterInfo, v1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			err = c.saveClusterInfo()
			if err != nil {
				return err
			}
			return nil
		}
		return err
	}
	data, ok := cm.BinaryData[clusterInfoKey]
	if ok {
		clusterInfo := &types.TensorCluster{}
		err = json.Unmarshal(data, clusterInfo)
		if err != nil {
			return err
		}
		c.CusterID = clusterInfo.Key
		return nil
	}
	return fmt.Errorf("no cluster key")
}

func (c *ClusterAgent) saveClusterInfo() error {
	clusterKey := uuid.NewUUID()
	cluster := &types.TensorCluster{
		Key:         string(clusterKey),
		Name:        c.Name,
		Description: "",
		Status:      0,
		ConsoleURL:  c.masterAddr,
	}

	data, err := json.Marshal(cluster)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: v1.ObjectMeta{Name: clusterInfo, Namespace: c.workerNamespace, Finalizers: []string{"security.cluster/cm-protection"}},
		BinaryData: map[string][]byte{clusterInfoKey: data},
	}
	_, err = c.HostClient.CoreV1().ConfigMaps(c.workerNamespace).Create(context.TODO(), cm, v1.CreateOptions{})
	if err != nil {
		return err
	}
	c.CusterID = string(clusterKey)
	return nil
}

func (c *ClusterAgent) GetHostClient() *assets.Clientset {
	return c.HostClient
}

package clustermanager

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
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
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
)

const APIKey = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"

const (
	defaultK8sClusterName = "default"
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

type ClusterManager struct {
	masterAddr      string
	CusterID        string
	Name            string
	KubeRestConfig  *k8s.K8SInfoForRestConfig
	apiServerAddr   string
	description     string
	ClusterType     model.ClusterType
	httpClient      *http.Client
	tlsClient       bool
	workerNamespace string
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

func NewClusterManager(config *config.Config) *ClusterManager {
	return &ClusterManager{
		masterAddr:      config.MasterAddr,
		Name:            config.Name,
		apiServerAddr:   config.APIServerAddr,
		workerNamespace: config.WorkerNamespace,
	}
}

func (c *ClusterManager) getHTTPClient() (*http.Client, error) {
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

func (c *ClusterManager) Init() error {
	client, err := c.getHTTPClient()
	if err != nil {
		return err
	}

	c.httpClient = client

	if c.Name == defaultK8sClusterName {
		c.ClusterType = model.HostCluster
		clusterConfig, err := rest.InClusterConfig()
		if err != nil {
			return err
		}
		c.CusterID = fmt.Sprintf("%d", util.GenerateUUID(defaultK8sClusterName, clusterConfig.Host))
		c.apiServerAddr = clusterConfig.Host

	} else {
		c.CusterID = fmt.Sprintf("%d", util.GenerateUUID(c.Name, c.apiServerAddr))
		c.ClusterType = model.MemberCluster
	}

	restConfig := &k8s.K8SInfoForRestConfig{
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
	logging.Get().Info().Msgf("cluster id : %s", c.CusterID)
	return nil
}

func (c *ClusterManager) Run() {

	stopChan := make(chan struct{})
	wait.Until(func() {
		err := c.registerClusterInfo()
		if err == nil {
			close(stopChan)
		}
	}, time.Second*60, stopChan)
	logging.Get().Info().Msg("successfully registered to master cluster")
}

type TensorCluster struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      int32  `json:"status"`
}

func (c *ClusterManager) registerClusterInfo() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	cluster := &model.TensorCluster{
		Key:                 c.CusterID,
		Name:                c.Name,
		ClusterType:         c.ClusterType,
		Description:         c.description,
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

func (c ClusterManager) updateClusterInfo() {
	type updateCluster struct {
		ClusterKey  string `json:"cluster_key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	req := updateCluster{
		ClusterKey:  c.CusterID,
		Name:        c.Name,
		Description: c.description,
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

func fullHTTPSUrl(str string) string {
	if strings.Contains(str, "https") {
		return str
	}
	return "https://" + str
}

func buildURL(host, path string) string {
	if strings.Contains(host, "http") {
		return host + path
	}
	return "http://" + host + path
}

func buildInClusterInfo() *model.TensorCluster {
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil
	}

	token := clusterConfig.BearerToken

	ca, err := ioutil.ReadFile(clusterConfig.TLSClientConfig.CAFile)
	if err != nil {
		logging.Get().Err(err).Msgf("read cluster ca file error: %s", clusterConfig.TLSClientConfig.CAFile)
		return nil
	}

	key := fmt.Sprintf("%d", util.GenerateUUID(defaultK8sClusterName, clusterConfig.Host))
	newCluster := &model.TensorCluster{
		Key:                 key,
		Name:                defaultK8sClusterName,
		ClusterType:         model.HostCluster,
		APIServerAddr:       clusterConfig.Host,
		SecretToken:         token,
		CertificateAuthData: string(ca),
	}
	return newCluster
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

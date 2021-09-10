package clusterManager

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/avast/retry-go"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
	"net/http"
	"strings"
	"time"
)

const ApiKey = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"

const (
	defaultK8sClusterName = "default"
)

type ClusterManager struct {
	masterAddr    string
	CusterID      string
	Name          string
	Token         string
	CaData        string
	apiServerAddr string
	description   string
	ClusterType   model.ClusterType
	httpClient    *http.Client
	tlsClient     bool
	client        clientset.Interface
	nodeInformer  coreinformers.NodeInformer
	resyncPeriod  time.Duration
}

const (
	tokenFile      = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	rootCAFile     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	masterAssetUrl = "/internal/platform/assets/cluster"
	tlsCAFile      = "/etc/tensorsec/cluster-manager/tls.crt"
	tlsKeyFile     = "/etc/tensorsec/cluster-manager/tls.key"
)

func NewClusterManager(config *config.Config) *ClusterManager {
	return &ClusterManager{
		masterAddr:    config.MasterAddr,
		Name:          config.Name,
		apiServerAddr: fullHttpsUrl(config.ApiServerAddr),
	}
}

func (c *ClusterManager) getHttpClient() (*http.Client, error) {
	if c.tlsClient {
		caCert, err := ioutil.ReadFile(tlsCAFile)
		if err != nil {
			logging.GetLogger().Err(err).Msg("open /auth/ca/tls.crr error")
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
				TLSClientConfig: &tls.Config{
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
	client, err := c.getHttpClient()
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
		c.Token = clusterConfig.BearerToken
		c.apiServerAddr = clusterConfig.Host

		ca, err := ioutil.ReadFile(clusterConfig.TLSClientConfig.CAFile)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("read cluster ca file error: %s", clusterConfig.TLSClientConfig.CAFile)
			return err
		}
		c.CaData = string(ca)
	} else {
		c.CusterID = fmt.Sprintf("%d", util.GenerateUUID(c.Name, c.apiServerAddr))
		c.ClusterType = model.MemberCluster
		token, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			return err
		}

		c.Token = string(token)

		if _, err := certutil.NewPool(rootCAFile); err != nil {
			logging.GetLogger().Err(err).Msg("load-file-err")
			return err
		} else {
			caData, err := ioutil.ReadFile(rootCAFile)
			if err != nil {
				return err
			}
			c.CaData = string(caData)
		}
	}
	logging.GetLogger().Info().Msgf("cluster id : %s", c.CusterID)
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
	logging.GetLogger().Info().Msg("successfully registered to master cluster")
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

	var cluster *model.TensorCluster

	cluster = &model.TensorCluster{
		Key:                 c.CusterID,
		Name:                c.Name,
		ClusterType:         c.ClusterType,
		Description:         c.description,
		APIServerAddr:       c.apiServerAddr,
		CertificateAuthData: c.CaData,
		SecretToken:         c.Token,
		Status:              0,
	}

	data, err := json.Marshal(cluster)
	if err != nil {
		logging.GetLogger().Err(err).Msg("Failed to marshal cluster")
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, buildUrl(c.masterAddr, masterAssetUrl), bytes.NewReader(data))
	if err != nil {
		return err
	}
	respHandler := func(resp *http.Response, err error) error {
		if err != nil {
			logging.GetLogger().Err(err).Msgf("post cluster info err : %v", err)
			return err
		}

		if resp.StatusCode != http.StatusOK {
			logging.GetLogger().Error().Msgf("http resp error: %s", resp.Status)
			return fmt.Errorf("http resp error: %s", resp.Status)
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logging.GetLogger().Debug().Msg(string(data))
		return nil
	}

	logging.GetLogger().Debug().Msgf("post cluster info to master cluster %v", string(data))
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
		logging.GetLogger().Err(err).Msg("Failed to marshal cluster")
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, buildUrl(c.masterAddr, masterAssetUrl), bytes.NewReader(data))
	if err != nil {
		return
	}

	respHandler := func(resp *http.Response, err error) error {
		if err != nil {
			logging.GetLogger().Err(err).Msg("post cluster info err")
			return err
		}

		if resp.StatusCode != http.StatusOK {
			logging.GetLogger().Error().Msgf("http resp error: %s", resp.Status)
			return fmt.Errorf("http resp error: %s", resp.Status)
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logging.GetLogger().Debug().Msg(string(data))
		return nil
	}

	logging.GetLogger().Debug().Msgf("post cluster info to master cluster %s", string(data))
	err = util.HTTPRequest(ctx, c.httpClient, request, respHandler, retry.Attempts(3))
	if err != nil {
		logging.GetLogger().Err(err).Msg("post cluster info to master cluster err")
		return
	}
}

func fullHttpsUrl(str string) string {
	if strings.Contains(str, "https") {
		return str
	}
	return "https://" + str
}

func buildUrl(host, path string) string {
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
		logging.GetLogger().Err(err).Msgf("read cluster ca file error: %s", clusterConfig.TLSClientConfig.CAFile)
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

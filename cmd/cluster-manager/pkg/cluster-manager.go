package clusterManager

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/avast/retry-go"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	certutil "k8s.io/client-go/util/cert"
	"net/http"
	"strings"
	"time"
)

const ApiKey = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"

type ClusterManager struct {
	masterAddr    string
	CusterID      string
	Name          string
	Token         string
	CaData        string
	apiServerAddr string
	description   string
	httpClient    *http.Client
	tlsClient     bool
	client        clientset.Interface
	nodeInformer  coreinformers.NodeInformer
	resyncPeriod  time.Duration
}

const (
	tokenFile      = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	rootCAFile     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	masterAssetUrl = "/api/openapi/assets/cluster"
	tlsCAFile      = "/etc/tensorsec/cluster-manager/tls.crt"
	tlsKeyFile     = "/etc/tensorsec/cluster-manager/tls.key"
)

func NewClusterManager(config *config.Config) *ClusterManager {

	clusterID := fmt.Sprintf("%d", util.GenerateUUID(config.Name, config.ApiServerAddr))
	logrus.Infof("cluster id : %s", clusterID)

	return &ClusterManager{
		masterAddr:    config.MasterAddr,
		Name:          config.Name,
		apiServerAddr: fullHttpsUrl(config.ApiServerAddr),
		CusterID:      clusterID,
	}
}

func (c *ClusterManager) getHttpClient() (*http.Client, error) {
	if c.tlsClient {
		caCert, err := ioutil.ReadFile(tlsCAFile)
		if err != nil {
			logrus.Error("open /auth/ca/tls.crr error")
			return nil, err
		}

		clientCertPool := x509.NewCertPool()
		if !clientCertPool.AppendCertsFromPEM(caCert) {
			return nil, err
		}

		cert, err := tls.LoadX509KeyPair(tlsCAFile, tlsKeyFile)
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

	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return err
	}

	c.Token = string(token)

	if _, err := certutil.NewPool(rootCAFile); err != nil {
		logging.GetLogger().Error().Str("load-file-err", err.Error())
	} else {
		caData, err := ioutil.ReadFile(rootCAFile)
		if err != nil {
			return err
		}
		c.CaData = string(caData)
	}
	return nil
}

func (c *ClusterManager) Run() {
	c.register()
	wait.Until(c.register, time.Second*60, wait.NeverStop)
}

func (c *ClusterManager) register() {
	err := c.registerClusterInfo()
	if err != nil {
		logrus.Errorf("failed to registre to master cluter: %v", err)
		return
	}
}

func (c *ClusterManager) registerClusterInfo() error {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	cluster := &model.TensorCluster{
		Key:                 c.CusterID,
		Name:                c.Name,
		Description:         c.description,
		APIServerAddr:       c.apiServerAddr,
		CertificateAuthData: c.CaData,
		SecretToken:         c.Token,
		Status:              0,
	}

	data, err := json.Marshal(cluster)
	if err != nil {
		logrus.Errorf("Failed to marshal cluster %v", err)
		logging.GetLogger().Error().Str("cluster manager err", "Failed to marshal cluster")
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, buildUrl(c.masterAddr, masterAssetUrl), bytes.NewReader(data))
	if err != nil {
		return err
	}
	respHandler := func(resp *http.Response, err error) error {
		if err != nil {
			logrus.Errorf("post cluster info err : %v", err)
			return err
		}

		if resp.StatusCode != http.StatusOK {
			logrus.Errorf("http resp error: %s", resp.Status)
			return fmt.Errorf("http resp error: %s", resp.Status)
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logrus.Debug(string(data))
		return nil
	}

	logrus.Debugf("post cluster info to master cluster %v", string(data))

	request.Header.Set("X-Tensorsec-cicd-key", ApiKey)
	err = util.HTTPRequest(ctx, c.httpClient, request, respHandler, retry.Attempts(3))
	if err != nil {
		return err
	}
	return nil
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

package clusterserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	json "github.com/json-iterator/go"
	param "github.com/oceanicdev/chi-param"
	"k8s.io/client-go/rest"

	clusterAgent "gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/attack"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/security-rd/go-pkg/logging"
)

type ClusterServer struct {
	server             *http.Server
	engine             *gin.Engine
	ClusterID          string
	Name               string
	TLSServer          bool
	config             *config.Config
	clusterManager     *k8s.ClusterManager
	attackCacheService *attack.CacheService
}

func (cs *ClusterServer) SetClusterManager(cm *k8s.ClusterManager) {
	cs.clusterManager = cm
}
func (cs *ClusterServer) handleClusterQuery(c *gin.Context) {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	clusterInfo := &TensorCluster{
		Key:         cs.ClusterID,
		Name:        cs.config.Name,
		ConsoleURL:  getConsoleURLPrefix(cs.config.MasterAddr),
		Description: "",
		Status:      0,
		K8SRestConfig: &k8s.InfoForRestConfig{
			CertData:      kubeConfig.CertData,
			KeyData:       kubeConfig.KeyData,
			CAData:        kubeConfig.CAData,
			Token:         []byte(kubeConfig.BearerToken),
			APIServerAddr: kubeConfig.Host,
		},
	}

	c.JSON(http.StatusOK, clusterInfo)
}

func (cs *ClusterServer) handleWatchCluster(c *gin.Context) {
	if cs.clusterManager == nil {
		c.String(http.StatusInternalServerError, "fail to watch: this not the host cluster")
		return
	}

	var tensorCluster model.TensorCluster

	err := c.ShouldBindJSON(&tensorCluster)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	err = cs.clusterManager.UpdateCluster(ctx, &tensorCluster)
	if err != nil {
		logging.Get().Err(err).Msg("watch cluster err.")

		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, "OK")
}

func (cs *ClusterServer) handleATTACKLatestData(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c, time.Second*2)
	defer cancel()

	reqVersion, err := param.QueryInt64(c.Request, "curVersion")
	if err != nil {
		logging.Get().Err(err).Int64("reqVersion", reqVersion).Msg("parse curVersion err")
		c.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
			Error: &response.HTTPError{
				Code:    1,
				Message: err.Error(),
			},
		})
		return
	}

	reqDataVersion, err := param.QueryInt64(c.Request, "curDataVersion")
	if err != nil {
		reqDataVersion = 0
	}
	reqSettingVersion, err := param.QueryInt64(c.Request, "curSettingVersion")
	if err != nil {
		reqSettingVersion = 0
	}

	data, err := cs.attackCacheService.GetLatestData(ctx, reqVersion, reqDataVersion, reqSettingVersion)
	if err != nil {
		logging.Get().Err(err).Int64("reqDataVersion", reqDataVersion).Int64("reqSettingVersion", reqSettingVersion).Msg("get latest data err")
		c.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
			Error: &response.HTTPError{
				Code:    1,
				Message: err.Error(),
			},
		})
		return
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logging.Get().Err(err).Int64("reqDataVersion", reqDataVersion).Int64("reqSettingVersion", reqSettingVersion).Msg("marshal err")
		c.JSON(http.StatusInternalServerError, response.HTTPEnvelope{
			Error: &response.HTTPError{
				Code:    1,
				Message: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, response.HTTPEnvelope{
		Data: &response.HTTPData{
			Item: dataBytes,
		},
	})
}

func NewHTTPServer(agent *clusterAgent.ClusterAgent, config *config.Config) (*ClusterServer, error) {
	tlsConfig := &tls.Config{}
	if config.TLSServer {
		tlsKeyPair, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			logging.Get().Err(err).Msg("failed to load tls key from file")
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{tlsKeyPair}
	}

	s := &ClusterServer{
		ClusterID:          agent.CusterID,
		Name:               config.Name,
		config:             config,
		attackCacheService: attack.NewCacheService(config.MasterAddr, agent),
	}

	r := gin.Default()
	if config.Profile {
		pprof.Register(r)
	}
	r.GET("/internal/cluster", s.handleClusterQuery)
	r.GET("/internal/watch_cluster", s.handleWatchCluster)
	r.GET("/api/openapi/ATTCK/latestData", s.handleATTACKLatestData)

	s.engine = r

	return s, nil
}

func (cs *ClusterServer) Run() {
	var err error
	if cs.TLSServer {
		err = cs.engine.RunTLS(fmt.Sprintf(":%d", cs.config.Port), cs.config.CertFile, cs.config.KeyFile)
	} else {
		err = cs.engine.Run(fmt.Sprintf(":%d", cs.config.Port))
	}

	if err != nil {
		logging.Get().Err(err).Msg("listen tcp address failed")
		return
	}
}

func getConsoleURLPrefix(masterAddr string) string {
	if strings.Contains(masterAddr, "http") {
		return masterAddr
	}
	return "http://" + masterAddr
}

package clusterserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ClusterServer struct {
	server         *http.Server
	engine         *gin.Engine
	ClusterID      string
	Name           string
	TLSServer      bool
	config         *config.Config
	clusterManager *k8s.ClusterManager
}

func (cs *ClusterServer) SetClusterManager(cm *k8s.ClusterManager) {
	cs.clusterManager = cm
}
func (cs *ClusterServer) handleClusterQuery(c *gin.Context) {
	clusterInfo := &TensorCluster{
		Key:           cs.ClusterID,
		Name:          cs.config.Name,
		ConsoleURL:    getConsoleURLPrefix(cs.config.MasterAddr),
		Description:   "",
		Status:        0,
		K8SRestConfig: cs.config.K8SInfoForRestConfig,
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

func NewHTTPServer(clusterKey string, config *config.Config) (*ClusterServer, error) {

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
		ClusterID: clusterKey,
		Name:      config.Name,
		config:    config,
	}

	r := gin.Default()
	r.GET("/internal/cluster", s.handleClusterQuery)
	r.GET("/internal/watch_cluster", s.handleWatchCluster)

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

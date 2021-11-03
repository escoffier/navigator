package clusterserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"k8s.io/client-go/rest"
)

const defaultK8sClusterName = "default"

type ClusterServer struct {
	server    *http.Server
	ClusterID string
	Name      string
	TlsServer bool
	config    *config.Config

	clusterManager *k8s.ClusterManager
}

func (cs *ClusterServer) SetClusterManager(cm *k8s.ClusterManager) {
	cs.clusterManager = cm
}
func (cs *ClusterServer) handleClusterQuery(w http.ResponseWriter, r *http.Request) {
	clusterInfo := &TensorCluster{
		Key:         cs.ClusterID,
		Name:        cs.config.Name,
		ConsoleUrl:  getConsoleUrlPrefix(cs.config.MasterAddr),
		Description: "",
		Status:      0,
	}
	data, err := json.Marshal(clusterInfo)
	if err != nil {
		http.Error(w, "failed to process cluster info", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(data)
	if err != nil {
		http.Error(w, "failed to process cluster info", http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
}

type watchResp struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func (cs *ClusterServer) handleWatchCluster(w http.ResponseWriter, r *http.Request) {
	resp := watchResp{}

	defer func() {
		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "failed to process cluster info", http.StatusInternalServerError)
			return
		}
		_, err = w.Write(data)
		if err != nil {
			http.Error(w, "failed to process cluster info", http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
	}()

	if cs.clusterManager == nil || cs.Name != "default" {
		resp.Status = 1
		resp.Message = "fail to watch: this not the host cluster"
		w.WriteHeader(400)
		return
	}

	dataBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logging.GetLogger().Err(err).Msg("handleWatchCluster read body err")
		resp.Status = 1
		resp.Message = err.Error()
		w.WriteHeader(500)
		return
	}
	var tensorCluster model.TensorCluster
	err = json.Unmarshal(dataBytes, &tensorCluster)
	if err != nil {
		logging.GetLogger().Err(err).Msg("json decode err.")
		resp.Status = 1
		resp.Message = err.Error()
		w.WriteHeader(500)
		return
	}

	err = cs.clusterManager.WatchClusterLocally(context.Background(), &tensorCluster)
	if err != nil {
		logging.GetLogger().Err(err).Msg("watch cluster err.")
		resp.Status = 1
		resp.Message = err.Error()
		w.WriteHeader(500)
		return
	}
	resp.Status = 0
	resp.Message = "OK"
}

func NewHttpServer(config *config.Config) (*ClusterServer, error) {

	tlsConfig := &tls.Config{}
	if config.TlsServer {
		tlsKeyPair, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			logging.GetLogger().Err(err).Msg("failed to load tls key from file")
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{tlsKeyPair}
	}

	cs := &http.Server{
		Addr:      fmt.Sprintf("0.0.0.0:%d", config.Port),
		TLSConfig: tlsConfig,
	}

	clusterID := getClusterID(config.Name, config.ApiServerAddr)
	s := &ClusterServer{
		ClusterID: clusterID,
		Name:      config.Name,
		config:    config,
	}

	mutex := http.NewServeMux()
	mutex.HandleFunc("/internal/cluster", s.handleClusterQuery)
	mutex.HandleFunc("/internal/watch_cluster", s.handleWatchCluster)

	cs.Handler = mutex

	s.server = cs
	s.TlsServer = config.TlsServer
	return s, nil
}

func (s *ClusterServer) Run() {
	var err error
	if s.TlsServer {
		err = s.server.ListenAndServeTLS("", "")
	} else {
		err = s.server.ListenAndServe()
	}

	if err != nil {
		logging.GetLogger().Err(err).Msg("listen tcp address failed")
		return
	}
}

func getClusterID(clusterName, apiServerAddr string) string {
	if clusterName == defaultK8sClusterName {
		clusterConfig, err := rest.InClusterConfig()
		if err != nil {
			logging.GetLogger().Err(err).Msg("get in ClusterConfig failed")
			return ""
		}
		return fmt.Sprintf("%d", util.GenerateUUID(defaultK8sClusterName, clusterConfig.Host))
	} else {
		return fmt.Sprintf("%d", util.GenerateUUID(clusterName, apiServerAddr))
	}
}

func getConsoleUrlPrefix(masterAddr string) string {
	if strings.Contains(masterAddr, "http") {
		return masterAddr
	}
	return "http://" + masterAddr
}

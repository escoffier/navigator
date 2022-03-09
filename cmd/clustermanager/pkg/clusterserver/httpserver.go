package clusterserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ClusterServer struct {
	server    *http.Server
	ClusterID string
	Name      string
	TLSServer bool
	config    *config.Config

	clusterManager *k8s.ClusterManager
}

func (cs *ClusterServer) SetClusterManager(cm *k8s.ClusterManager) {
	cs.clusterManager = cm
}
func (cs *ClusterServer) handleClusterQuery(w http.ResponseWriter, _ *http.Request) {
	clusterInfo := &TensorCluster{
		Key:           cs.ClusterID,
		Name:          cs.config.Name,
		ConsoleURL:    getConsoleURLPrefix(cs.config.MasterAddr),
		Description:   "",
		Status:        0,
		K8SRestConfig: cs.config.K8SInfoForRestConfig,
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	err = cs.clusterManager.UpdateCluster(ctx, &tensorCluster)
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

func NewHTTPServer(clusterKey string, config *config.Config) (*ClusterServer, error) {

	tlsConfig := &tls.Config{}
	if config.TLSServer {
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

	s := &ClusterServer{
		ClusterID: clusterKey,
		Name:      config.Name,
		config:    config,
	}

	mutex := http.NewServeMux()
	mutex.HandleFunc("/internal/cluster", s.handleClusterQuery)
	mutex.HandleFunc("/internal/watch_cluster", s.handleWatchCluster)

	cs.Handler = mutex

	s.server = cs
	s.TLSServer = config.TLSServer
	return s, nil
}

func (cs *ClusterServer) Run() {
	var err error
	if cs.TLSServer {
		err = cs.server.ListenAndServeTLS("", "")
	} else {
		err = cs.server.ListenAndServe()
	}

	if err != nil {
		logging.GetLogger().Err(err).Msg("listen tcp address failed")
		return
	}
}

func getConsoleURLPrefix(masterAddr string) string {
	if strings.Contains(masterAddr, "http") {
		return masterAddr
	}
	return "http://" + masterAddr
}

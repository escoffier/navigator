package clusterserver

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"net/http"
)

type ClusterServer struct {
	server    *http.Server
	CusterID  string
	Name      string
	TlsServer bool
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

	clusterID := fmt.Sprintf("%d", util.GenerateUUID(config.Name, config.ApiServerAddr))
	mutex := http.NewServeMux()
	mutex.HandleFunc("/internal/cluster", func(w http.ResponseWriter, r *http.Request) {
		clusterInfo := &TensorCluster{
			Key:         clusterID,
			Name:        config.Name,
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
	})

	cs.Handler = mutex

	return &ClusterServer{
		server:    cs,
		CusterID:  clusterID,
		Name:      config.Name,
		TlsServer: config.TlsServer}, nil
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

package cmd

import (
	"github.com/spf13/pflag"
	clusterManager "gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/clusterserver"
	conf "gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type server struct {
	config     *conf.Config
	manager    *clusterManager.ClusterManager
	httpserver *clusterserver.ClusterServer
}

var ServerConfig = &conf.Config{}

func NewServer() (*server, error) {
	s := &server{
		config: ServerConfig,
	}

	clsm := clusterManager.NewClusterManager(s.config)
	err := clsm.Init()
	if err != nil {
		logging.GetLogger().Error().Msg("faild to init cluster manager")
		return nil, err
	}

	s.manager = clsm

	httpserver, err := clusterserver.NewHttpServer(s.config)
	if err != nil {
		logging.GetLogger().Err(err).Msg("cluster server err")
		return nil, err
	}
	s.httpserver = httpserver
	return s, nil
}

func (s *server) Run() error {
	errChn := make(chan error)
	go s.manager.Run()
	go s.httpserver.Run()
	return <-errChn
}

func AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&ServerConfig.MasterAddr, "master-addr", "nil", "address of master cluster")
	fs.StringVar(&ServerConfig.Name, "cluster-name", "kubernetes-cluster", "set cluster name")
	fs.StringVar(&ServerConfig.ApiServerAddr, "api-server-address", "127.0.0.1:6443", "api server address of current cluster")
	fs.BoolVar(&ServerConfig.TlsClient, "tls-client", false, "use https client")
	fs.IntVar(&ServerConfig.Port, "port", 9443, "The port of inject server to listen.")
	fs.StringVar(&ServerConfig.CertFile, "tlsCertPath", "/etc/tensorsec/certs/tls.crt", "The path of tls cert")
	fs.StringVar(&ServerConfig.KeyFile, "tlsKeyPath", "/etc/tensorsec/certs/tls.key", "The path of tls key")
	fs.BoolVar(&ServerConfig.TlsServer, "tlsServer", false, "use tls server")
}

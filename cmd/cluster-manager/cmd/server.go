package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	clusterManager "gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/config"
)

type server struct {
	config config.Config
	clsm   *clusterManager.ClusterManager
}

func NewServer() *server {
	return &server{}
}

func (s *server) Run() error {
	errChn := make(chan error)
	go s.clsm.Run()
	return <-errChn
}

func (s *server) Init() error {
	s.clsm = clusterManager.NewClusterManager(&s.config)
	err := s.clsm.Init()
	if err != nil {
		logrus.Error("faild to init cluster manager")
		return err
	}
	return nil
}

func (s *server) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.config.MasterAddr, "master-addr", "nil", "address of master cluster")
	fs.StringVar(&s.config.Name, "cluster-name", "kubernetes-cluster", "set cluster name")
	fs.StringVar(&s.config.ApiServerAddr, "api-server-address", "127.0.0.1:6443", "api server address of current cluster")
	fs.BoolVar(&s.config.TlsClient, "tls-client", false, "use https client")
}

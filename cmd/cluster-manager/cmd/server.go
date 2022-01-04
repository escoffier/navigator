package cmd

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/security-rd/go-pkg/databases"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	clusterManager "gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/clusterserver"
	conf "gitlab.com/piccolo_su/vegeta/cmd/cluster-manager/pkg/config"
	pkgassets "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"gorm.io/gorm"
)

type server struct {
	config     *conf.Config
	manager    *clusterManager.ClusterManager
	httpserver *clusterserver.ClusterServer
}

var ServerConfig = &conf.Config{}

func NewServer(cmd *cobra.Command, args []string) (*server, error) {
	s := &server{
		config: ServerConfig,
	}

	s.initConfig()

	logging.GetLogger().Info().Msgf("config: %+v", s.config)

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

	if s.config.Name == clusterserver.HostClusterName {

		// Redis DB client
		redisEndpoints := os.Getenv("REDIS_CLUSTER_URL")
		if redisEndpoints == "" {
			return nil, errors.New("missing REDIS_CLUSTER_URL")
		}
		redisPassword := os.Getenv("REDIS_PASSWORD")
		if redisPassword == "" {
			return nil, errors.New("missing REDIS_PASSWORD")
		}
		sa := strings.Split(redisEndpoints, ",")
		redisClient, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{
			MasterName:    "mymaster",
			SentinelAddrs: sa,
			Password:      redisPassword,
			DB:            0,
		})
		if err != nil {
			return nil, err
		}

		rdb, err := rdbtools.GormWrapperOpen(3*time.Second, func() (*gorm.DB, error) {
			db, err := databases.GetMysqlWithEnv(context.Background())
			if err != nil {
				logging.GetLogger().Err(err).Msg(fmt.Sprintf("rdb client init error :%s ", err))
				return nil, err
			}
			return db, nil
		})
		if err != nil {
			logging.GetLogger().Err(err).Msg("Init postgre error")
			return nil, err
		}

		scannerHost := os.Getenv("SCANNER_HOST")
		scannerPort := os.Getenv("SCANNER_PORT")
		scannerURL := fmt.Sprintf("http://%s:%s", scannerHost, scannerPort)

		err = k8s.InitClusterManager(rdb, func(ctx context.Context) (*pkgassets.Watcher, error) {
			return assets.Watcher(rdb, redisClient, scannerURL)
		}, "")
		if err != nil {
			logging.GetLogger().Err(err).Msg("cluster manager init error")
			return nil, err
		}
		k8sManager, ok := k8s.GetClusterManager()
		if !ok {
			logging.GetLogger().Error().Msg("cluster manager init error")
			return nil, err
		} else {
			k8sManager.Start(context.Background())
			httpserver.SetClusterManager(k8sManager)
		}

	}

	return s, nil
}

func (s *server) Run() error {
	errChn := make(chan error)
	go s.manager.Run()
	go s.httpserver.Run()
	return <-errChn
}

func fullHttpsUrl(str string) string {
	if strings.Contains(str, "https") {
		return str
	}
	return "https://" + str
}

func (s *server) initConfig() {
	apiServerAddr := os.Getenv("API_SERVER_URL")
	if apiServerAddr != "" {
		s.config.ApiServerAddr = apiServerAddr
	} else {
		s.config.ApiServerAddr = fullHttpsUrl(s.config.ApiServerAddr)
	}

	workerNs := os.Getenv("MY_POD_NAMESPACE")
	s.config.WorkerNamespace = workerNs

	clusterName := os.Getenv("CLUSTER_NAME")
	if clusterName != "" {
		s.config.Name = clusterName
	}

	var consoleUrl string
	if clusterName == clusterserver.HostClusterName {
		consoleUrl = os.Getenv("CONSOLE_INTERNAL_URL")
	} else {
		consoleUrl = os.Getenv("CONSOLE_EXTERNAL_URL")
	}
	if consoleUrl != "" {
		s.config.MasterAddr = consoleUrl
	}
}

func AddFlags(fs *pflag.FlagSet, rootCmd *cobra.Command) {
	fs.StringVar(&ServerConfig.MasterAddr, "master-addr", "nil", "address of master cluster")
	fs.StringVar(&ServerConfig.Name, "cluster-name", "kubernetes-cluster", "set cluster name")
	fs.StringVar(&ServerConfig.ApiServerAddr, "api-server-address", "127.0.0.1:6443", "api server address of current cluster")
	fs.BoolVar(&ServerConfig.TlsClient, "tls-client", false, "use https client")
	fs.IntVar(&ServerConfig.Port, "port", 9443, "The port of inject server to listen.")
	fs.StringVar(&ServerConfig.CertFile, "tlsCertPath", "/etc/cluster-manager/certs/tls.crt", "The path of tls cert")
	fs.StringVar(&ServerConfig.KeyFile, "tlsKeyPath", "/etc/cluster-manager/certs/tls.key", "The path of tls key")
	fs.BoolVar(&ServerConfig.TlsServer, "tlsServer", false, "use tls server")
}

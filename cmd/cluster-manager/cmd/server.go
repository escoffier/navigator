package cmd

import (
	"context"
	"fmt"
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
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"gorm.io/driver/postgres"
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
		postgresOpts := flag.GetPostgresOpts(cmd)
		logging.GetLogger().Info().
			Str("postgres connection", postgresOpts.PostgresConnectionString).
			Str("pvc", postgresOpts.PVC).
			Str("pod", postgresOpts.Pod).
			Str("dataPath", postgresOpts.DataPath).
			Msg("Postgres options")

		scannerOpts := flag.GetVegetaScannerOpts(cmd)
		logging.GetLogger().Info().
			Str("host", scannerOpts.Host).
			Int("port", scannerOpts.Port).
			Msg("Vegeta Scanner options")

		redisOpts := flag.GetRedisOpts(cmd)
		logging.GetLogger().Info().
			Str("endpoint", redisOpts.Endpoint).
			Msg("Redis options")

		// Redis DB client
		sa := strings.Split(redisOpts.Endpoint, ",")
		redisClient, err := redistools.NewTensorRedisClient(&redis.FailoverOptions{
			MasterName:    "mymaster",
			SentinelAddrs: sa,
			Password:      os.Getenv("TENSORSEC_REDIS_PASSWORD"),
			DB:            0,
		})
		if err != nil {
			return nil, err
		}

		PgDsn := postgresOpts.PostgresConnectionString
		postgresDB, err := rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
			db, err := gorm.Open(postgres.Open(PgDsn), &gorm.Config{})
			if err != nil {
				logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
				return nil, err
			}
			sqlDB, err := db.DB()
			if err == nil {
				sqlDB.SetMaxOpenConns(30)
				sqlDB.SetMaxIdleConns(5)
				sqlDB.SetConnMaxLifetime(time.Hour)
			}
			return db, nil
		})
		if err != nil {
			logging.GetLogger().Err(err).Msg("Init postgre error")
			return nil, err
		}

		scannerURL := fmt.Sprintf("http://%s:%d", scannerOpts.Host, scannerOpts.Port)

		err = k8s.InitClusterManager(postgresDB, func(ctx context.Context) (*pkgassets.Watcher, error) {
			return assets.Watcher(postgresDB, redisClient, scannerURL)
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
	s.config.ApiServerAddr = fullHttpsUrl(s.config.ApiServerAddr)
	workerNs := os.Getenv("MY_POD_NAMESPACE")
	s.config.WorkerNamespace = workerNs
}

func AddFlags(fs *pflag.FlagSet, rootCmd *cobra.Command) {
	fs.StringVar(&ServerConfig.MasterAddr, "master-addr", "nil", "address of master cluster")
	fs.StringVar(&ServerConfig.Name, "cluster-name", "kubernetes-cluster", "set cluster name")
	fs.StringVar(&ServerConfig.ApiServerAddr, "api-server-address", "127.0.0.1:6443", "api server address of current cluster")
	fs.BoolVar(&ServerConfig.TlsClient, "tls-client", false, "use https client")
	fs.IntVar(&ServerConfig.Port, "port", 9443, "The port of inject server to listen.")
	fs.StringVar(&ServerConfig.CertFile, "tlsCertPath", "/etc/tensorsec/certs/tls.crt", "The path of tls cert")
	fs.StringVar(&ServerConfig.KeyFile, "tlsKeyPath", "/etc/tensorsec/certs/tls.key", "The path of tls key")
	fs.BoolVar(&ServerConfig.TlsServer, "tlsServer", false, "use tls server")
	flag.AddRedisFlags(rootCmd)
	flag.AddPostgresFlags(rootCmd)
	flag.AddVegetaScannerFlags(rootCmd)
}

package cmd

import (
	"context"
	"flag"
	"os"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	clusterAgent "gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg"
	apisecurity "gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/api-security"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/clusterserver"
	conf "gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/config"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/drift"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/microseg"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/service"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	assets2 "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/redisearch"
	"k8s.io/client-go/informers"
	"k8s.io/klog/v2"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"
)

const (
	defaultPort    = 9443
	EnvTopic       = "KAFKA_TOPIC"
	EnvGroupID     = "KAFKA_GROUP_ID"
	defaultTopic   = "kube-resources"
	defaultGroupID = "group-assets"
	resyncInterval = 8 * time.Hour
)

type server struct {
	config     *conf.Config
	agent      *clusterAgent.ClusterAgent
	httpserver *clusterserver.ClusterServer
}

var ServerConfig = &conf.Config{}
var microsegv2 = false

func NewServer() (*server, error) {
	s := &server{
		config: ServerConfig,
	}

	s.loadConfig()

	logging.Get().Info().Msgf("config: %+v", s.config)

	agent := clusterAgent.NewClusterAgent(s.config)
	err := agent.Init()
	if err != nil {
		logging.Get().Err(err).Msg("failed to init cluster manager")
		return nil, err
	}

	inClusterStream := rpcstream.NewStreamFactory(rpcstream.WithPodNameKey()).Server("tcp", ":19090")
	_ = inClusterStream.Start()

	stream := rpcstream.NewStreamFactory(rpcstream.WithClusterKey(agent.CusterID)).Client(s.config.MasterGrpcAddr)
	_ = stream.AddHandler(&pb.HoneySpotReq{}, &service.HoneypotHandler{
		KubeClient: agent.GetHostClient(),
	})
	_ = stream.AddHandler(&pb.ImageSecReq{}, &service.ImageSecHandler{
		ServerStream: inClusterStream,
		ClusterKey:   agent.CusterID,
	})
	_ = stream.AddHandler(&pb.ComplianceScanReq{}, &scapper.ProxyHandler{ServerStream: inClusterStream})
	_ = stream.Start()

	agent.Stream = stream

	s.agent = agent

	httpserver, err := clusterserver.NewHTTPServer(agent, s.config)
	if err != nil {
		logging.Get().Err(err).Msg("cluster server err")
		return nil, err
	}
	s.httpserver = httpserver

	stopChan := make(chan struct{})

	factory := informers.NewSharedInformerFactory(agent.GetHostClient(), resyncInterval)
	tensorFactory := externalversions.NewSharedInformerFactory(agent.GetHostClient().TensorClientset, resyncInterval)

	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		return nil, err
	}
	go assets.NewAssetsController(factory, tensorFactory, mqWriter, agent.CusterID, "kube-resources", s.config.PoolInfo).Run(stopChan)

	if microsegv2 {
		go microseg.NewNetworkPolicyController(agent.GetHostClient().TensorClientset, factory, tensorFactory).Run(stopChan)
	}

	if s.config.ClusterType == model.HostCluster {
		rdb, err := databases.NewRDBWithMySQLByEnv(context.Background())
		if err != nil {
			logging.Get().Err(err).Msg("Init db error")
			return nil, err
		}

		if s.config.DBLogDebug {
			rdb.SetDebugMode()
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		version, err := k8s.GetProductVersionFrom(context.Background(), agent.HostClient, clusterAgent.MyResourcePrefix, s.config.WorkerNamespace)
		if err != nil {
			logging.Get().Err(err).Msg("failed to get product version")
		}

		tensorCluster := &model.TensorCluster{
			Key:                 agent.CusterID,
			Name:                agent.Name,
			Description:         agent.Description,
			ClusterType:         agent.ClusterType,
			APIServerAddr:       agent.KubeRestConfig.APIServerAddr,
			CertificateAuthData: string(agent.KubeRestConfig.CAData),
			SecretToken:         string(agent.KubeRestConfig.Token),
			ClientCertData:      string(agent.KubeRestConfig.CertData),
			ClientKeyData:       string(agent.KubeRestConfig.KeyData),
			WorkerNamespace:     s.config.WorkerNamespace,
			Platform:            agent.Platform(),
			Version:             version,
		}

		err = dal.AddCluster(ctx, rdb.Get(), tensorCluster)
		if err != nil {
			logging.Get().Err(err).Msg("failed to add cluster")
			return nil, err
		}

		err = k8s.InitClusterManager(agent.GetHostClient(), tensorFactory, "")
		if err != nil {
			logging.Get().Err(err).Msg("cluster manager init error")
			return nil, err
		}
		clusterManager, ok := k8s.GetClusterManager()
		if !ok {
			logging.Get().Error().Msg("cluster manager init error")
			return nil, err
		} else {
			clusterManager.Start()
			httpserver.SetClusterManager(clusterManager)

			err = clusterManager.UpdateCluster(ctx, tensorCluster)
			if err != nil {
				return nil, err
			}
		}

		scannerURL := os.Getenv("SCANNER_URL")
		if scannerURL == "" {
			scannerURL = "http://tensorsec-scanner:8888"
		}
		mqReader, err := mq.GetClientFactory().Reader(context.Background())
		if err != nil {
			return nil, err
		}

		kafkaTopic := os.Getenv(EnvTopic)
		if kafkaTopic == "" {
			kafkaTopic = defaultTopic
		}
		kafkaGroupID := os.Getenv(EnvGroupID)
		if kafkaGroupID == "" {
			kafkaTopic = defaultGroupID
		}
		// Redis DB client
		redisClient, err := cache.NewRedis()
		if err != nil {
			return nil, err
		}

		var searchClient *redisearch.Client

		if os.Getenv("USE_REDISEARCH") != "false" {
			searchClient, err = redisearch.NewClient()
			if err != nil {
				return nil, err
			}
		}

		w, err := assets.Watcher(rdb, redisClient, searchClient, scannerURL, mqReader, kafkaTopic, kafkaGroupID)
		if err != nil {
			return nil, err
		}
		go w.Run(stopChan)

		driftWatcher := drift.NewDriftSupport(rdb, mqReader, model.SubjectOfDriftSupportEvent, "group-support-info")
		go driftWatcher.Start(stopChan)

		apiWatcher := apisecurity.NewWatcher(mqReader, "security-api", "api-security", rdb)
		go apiWatcher.Run(stopChan)
	}

	factory.Start(stopChan)
	tensorFactory.Start(stopChan)

	factory.WaitForCacheSync(stopChan)
	tensorFactory.WaitForCacheSync(stopChan)

	return s, nil
}

func (s *server) Run() error {
	errChn := make(chan error)

	if s.config.ClusterType == model.MemberCluster {
		go s.agent.RegisterToHostCluster()
	}

	go s.httpserver.Run()
	logging.Get().Info().Msg("clusterManage server run")
	return <-errChn
}

func fullHTTPSURL(str string) string {
	if strings.Contains(str, "https") {
		return str
	}
	return "https://" + str
}

func (s *server) loadConfig() {
	apiServerAddr := os.Getenv("INNER_API_SERVER_URL")
	if apiServerAddr != "" {
		s.config.APIServerAddr = apiServerAddr
	} else if s.config.APIServerAddr != "" {
		s.config.APIServerAddr = fullHTTPSURL(s.config.APIServerAddr)
	}

	externalAPIServerAddr := os.Getenv("API_SERVER_URL")
	if externalAPIServerAddr != "" {
		s.config.ExternalAPIServerAddr = externalAPIServerAddr
	}

	workerNs := os.Getenv("MY_POD_NAMESPACE")
	s.config.WorkerNamespace = workerNs

	clusterName := os.Getenv("CLUSTER_NAME")
	if clusterName != "" {
		s.config.Name = clusterName
	}

	isHostCluster := os.Getenv("IS_MAIN_CLUSTER")
	if isHostCluster == "true" {
		s.config.ClusterType = model.HostCluster
		s.config.MasterAddr = os.Getenv("CONSOLE_INTERNAL_URL")
		s.config.MasterGrpcAddr = os.Getenv("CONSOLE_INTERNAL_GRPC_ADDR")
	} else {
		s.config.ClusterType = model.MemberCluster
		s.config.MasterAddr = os.Getenv("CONSOLE_EXTERNAL_URL")
		s.config.MasterGrpcAddr = os.Getenv("CONSOLE_EXTERNAL_GRPC_ADDR")
	}
	poolData := os.Getenv("POOL_INFO")
	poolInfo := &assets2.PoolInfo{}
	if poolData != "" {
		err := json.Unmarshal([]byte(poolData), poolInfo)
		if err != nil {
			logging.Get().Err(err).Msg("Unmarshal pool info err")
			return
		}
		s.config.PoolInfo = poolInfo
		logging.Get().Info().Msgf("poolInfo: %v", poolInfo)
	}
	microsegEnv := os.Getenv("MICROSEGV2")
	if microsegEnv == "true" {
		microsegv2 = true
	}
}

func AddFlags(fs *pflag.FlagSet, rootCmd *cobra.Command) {
	fs.StringVar(&ServerConfig.MasterAddr, "master-addr", "nil", "address of master cluster")
	fs.StringVar(&ServerConfig.Name, "cluster-name", "kubernetes-cluster", "set cluster name")
	fs.StringVar(&ServerConfig.APIServerAddr, "api-server-address", "", "api server address of current cluster")
	fs.BoolVar(&ServerConfig.TLSClient, "tls-client", false, "use https client")
	fs.IntVar(&ServerConfig.Port, "port", defaultPort, "The port of inject server to listen.")
	fs.StringVar(&ServerConfig.CertFile, "tlsCertPath", "/etc/cluster-manager/certs/tls.crt", "The path of tls cert")
	fs.StringVar(&ServerConfig.KeyFile, "tlsKeyPath", "/etc/cluster-manager/certs/tls.key", "The path of tls key")
	fs.BoolVar(&ServerConfig.TLSServer, "tlsServer", false, "Enable tls for server")
	fs.BoolVar(&ServerConfig.DBLogDebug, "DBDebugLog", false, "Enable database debug log")
	fs.BoolVar(&ServerConfig.Profile, "profile", true, "Enable profiling via web interface host:port/debug/pprof")
}

func init() {
	klog.InitFlags(flag.CommandLine)
	err := flag.CommandLine.Lookup("v").Value.Set("3")
	if err != nil {
		return
	}
}

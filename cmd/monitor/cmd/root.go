package cmd

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"gitlab.com/piccolo_su/vegeta/cmd/monitor/pkg/metrics"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/heartbeat"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"os"
	"strconv"
)

var loggingOptions *logging.Options

func init() {

	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.Level = int(zerolog.TraceLevel)
	loggingOptions.AddFlags(flag.CommandLine)
}

func setLoggingLevel() {
	logLevel := zerolog.InfoLevel
	logLevelStr := os.Getenv("LOGGING_LEVEL")
	if logLevelStr != "" {
		ll, err := strconv.ParseInt(logLevelStr, 10, 8)
		if err == nil {
			logLevel = zerolog.Level(ll)
		}
	}
	logging.Get().SetLevel(logLevel)
}

func NewMonitorMetricsCommand() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "monitor",
		Short: "monitor",
		Run: func(cmd *cobra.Command, args []string) {
			// new instance
			monitor := NewMonitorServer()
			var stopCh <-chan struct{}
			go func() {
				stopCh = SetupSignalHandler()
				<-stopCh
			}()
			err := monitor.Run(stopCh)
			if err != nil {
				logging.Get().Err(err).Msgf("monitor down.")
			}
		},
	}

	if errs := loggingOptions.Validate(); len(errs) > 0 {
		logging.Get().Panic().Err(fmt.Errorf("%v", errs)).Msg("")
	}
	loggingOptions.SetConsoleWriterWrapper(logging.ConsoleCallerWriter)
	logging.ReplaceLogger(loggingOptions)

	setLoggingLevel()

	// add subcommand
	rootCmd.AddCommand(versionCmd)
	return rootCmd
}

type Server struct {
}

func NewMonitorServer() *Server {
	return &Server{}
}

func (m *Server) Run(stop <-chan struct{}) error {
	//
	client, err := K8sClient()
	if err != nil {
		return errors.Errorf("k8s client init failed, %v", err)
	}

	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		return errors.Errorf("get mq writer failed, %v", err)
	}

	clusterAddr := os.Getenv("CLUSTER_MANAGER_URL")
	if clusterAddr == "" {
		logging.Get().Warn().Msg("env CLUSTER_MANAGER_URL not found")
		return errors.Errorf("get cluster address failed.")
	}
	clusterManager := k8s.NewClusterInfoManager(clusterAddr)
	clusterKey, ok := clusterManager.ClusterKey()
	if !ok {
		logging.Get().Warn().Msg("get cluster key failed")
		return errors.Errorf("get cluster key failed.")
	}

	nodeName := os.Getenv(env.NodeName)
	if nodeName == "" {
		return errors.New("not found env:" + env.NodeName)
	}
	node, err := client.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})

	monitorTopic := os.Getenv(env.EnvTopicMonitor)
	if monitorTopic == "" {
		monitorTopic = env.DefaultTopicMonitor
	}
	namespace := os.Getenv(env.SoftName)
	if namespace == "" {
		return errors.New("not found env:" + env.SoftName)
	}

	softVersion := os.Getenv(env.SoftVersionEnv)
	if softVersion == "" {
		return errors.New("not found env:" + env.SoftVersionEnv)
	}

	sf := heartbeat.SelfInfo{
		ClusterKey: clusterKey,
		NodeName:   nodeName,
		Version:    softVersion,
		Namespace:  namespace,
	}
	watcher, err := metrics.NewMetricsWatcher(&sf, node.Status.NodeInfo.ContainerRuntimeVersion, mqWriter, monitorTopic)
	if err != nil {
		logging.Get().Err(err).Msgf("metricsWatcher init failed.")
		return err
	}
	go watcher.Run()
	//grpc
	nodeKey := fmt.Sprintf("%s-monitor", nodeName)
	clusterGrpcAddr := os.Getenv("CLUSTER_MANAGER_GRPC_ADDR")
	if clusterAddr == "" {
		logging.Get().Warn().Msg("env CLUSTER_MANAGER_GRPC_ADDR not found")
		return errors.Errorf("get cluster grpc address failed.")
	}
	rpcStream := rpcstream.NewStreamFactory(rpcstream.WithClusterKey(nodeKey)).Client(clusterGrpcAddr)
	_ = rpcStream.AddHandler(&pb.ContainerMetricsReq{}, watcher)
	rpcStream.Start()

	<-stop
	return nil
}

func K8sClient() (*kubernetes.Clientset, error) {
	config, err := k8s.KubeConfig()
	if err != nil {
		return nil, errors.Errorf("Couldn't initialize k8s config: %v", err)
	}
	// k8s client
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Errorf("Couldn't initialize k8s clientset: %v", err)
	}

	return k8sClient, nil
}

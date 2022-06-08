package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/netflow"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	_ "go.uber.org/automaxprocs"
)

var loggingOptions *logging.Options

func init() {
	rand.Seed(time.Now().UnixNano())

	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(flag.CommandLine)
}

const (
	// 定时上报，缓存的间隔和缓存大小，实现简单的频控
	defaultRTBuffInterval = 250 * time.Millisecond
	defaultRTBuffSize     = 100
)

func initEventStreams(udsAddr, nodeName string, cm *k8s.ClusterInfoManager, mqWriter mq.Writer, containerInfo nodeinfo.ContainerInfoManager, podResInfo *nodeinfo.PodResInfo) (*rtdetect.RuntimeEventStream, error) {
	bui := rtdetect.StreamBuilder(udsAddr, nodeName, cm)

	// add handlers here
	ecHandler := rtdetect.NewEventsOutputHandler(nodeName, mqWriter, containerInfo, podResInfo)
	bui.WithHandler(rtdetect.NewSyncHandler(ecHandler))

	s, err := bui.Build(context.Background())
	return s, err
}

func initNodeInfos(hostName, hostIP, clusterKey string) (nodeinfo.ContainerInfoManager, *netflow.NodePodsInfo, *nodeinfo.PodResInfo, *nodeinfo.NodePodsWatcher, error) {
	nodePods := nodeinfo.NewNodePodsWatcher(hostName, clusterKey)
	err := nodePods.Build().InitK8sClient()
	if err != nil {
		return nil, nil, nil, nil, errors.Errorf("k8s client init failed, %v", err)
	}

	containerType, err := nodePods.Build().GetContainerType()
	if err != nil {
		return nil, nil, nil, nil, errors.Errorf("get k8s node containerRuntimeVersion failed, %v", err)
	}

	var containerInfo nodeinfo.ContainerInfoManager
	switch containerType {
	case nodeinfo.DockerType:
		containerInfo, err = nodeinfo.NewDockerInfoManager(hostName, hostIP)
		if err != nil {
			return nil, nil, nil, nil, errors.Errorf("Failed to initialize docker info manager, %v", err)
		}
		logging.Get().Info().Msgf("new docker client success!")
	case nodeinfo.CrioType:
		containerInfo, err = nodeinfo.NewCrioInfoManager()
		if err != nil {
			return nil, nil, nil, nil, errors.Errorf("Failed to initialize cri-o info manager, %v", err)
		}
		logging.Get().Info().Msgf("new cri-o client success!")
	case nodeinfo.PodmanType:
		containerInfo, err = nodeinfo.NewPodmanInfoManager()
		if err != nil {
			return nil, nil, nil, nil, errors.Errorf("Failed to initialize podman info manager, %v", err)
		}
		logging.Get().Info().Msgf("new podman client success!")
	}

	err = containerInfo.Start()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("start dockerInfo listen failed, %v.", err)
	}

	k8sInfo := netflow.NewNodePodInfo(containerInfo)
	podResInfo := nodeinfo.NewPodResInfo()
	podsWatcher := nodePods.AddWatcher(k8sInfo).AddWatcher(podResInfo).Build()
	err = podsWatcher.Start(context.Background())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("start pods watcher error: %v", err)
	}

	return containerInfo, k8sInfo, podResInfo, podsWatcher, nil
}

var runes = []rune{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
}

func getClientID(hostName string) string {
	b := strings.Builder{}
	for _, by := range hostName {
		if (by >= 'a' && by <= 'z') || (by >= 'A' && by <= 'Z') || (by >= '0' && by <= '9') || by == '-' || by == '_' {
			b.WriteRune(by)
		} else {
			b.WriteRune(runes[rand.Intn(len(runes))])
		}
	}
	b.WriteRune('_')
	randNum := 5 + rand.Intn(5)
	for i := 0; i < randNum; i++ {
		b.WriteRune(runes[rand.Intn(len(runes))])
	}
	return b.String()
}

func GetEnvInfo() (string, string) {
	hostName := os.Getenv("MY_NODE_NAME")
	if hostName == "" {
		hostName = "Unknown"
	}

	hostIP := os.Getenv("MY_HOST_IP")
	if hostIP == "" {
		hostIP = "Unknown"
	}

	return hostName, hostIP
}

func Run(ctx context.Context) error {
	wg := sync.WaitGroup{}
	//get local env
	hostName, hostIP := GetEnvInfo()
	//get rt uds addr
	rtUdsAddr := os.Getenv("RTDETECT_UDS_ADDR")
	if rtUdsAddr == "" {
		logging.Get().Warn().Msg("env RTDETECT_UDS_ADDR not found")
	}
	clusterAddr := os.Getenv("CLUSTER_MANAGER_URL")
	if clusterAddr == "" {
		logging.Get().Warn().Msg("env CLUSTER_MANAGER_URL not found")
		return errors.Errorf("get cluster address failed.")
	}
	//get console address
	var consoleAddr, addrStr string
	clusterType := os.Getenv("IS_MAIN_CLUSTER")
	if clusterType == "true" {
		consoleAddr = os.Getenv("CONSOLE_INTERNAL_URL")
		addrStr = "CONSOLE_INTERNAL_URL"
	} else {
		consoleAddr = os.Getenv("CONSOLE_EXTERNAL_URL")
		addrStr = "CONSOLE_EXTERNAL_URL"
	}
	if consoleAddr == "" {
		logging.Get().Warn().Msgf("env %v not found", addrStr)
		return errors.Errorf("get console address failed.")
	}

	mqFactory := mq.GetClientFactory()
	mqWriter, err := mqFactory.Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("Init mq error")
	}

	clusterManager := k8s.NewClusterInfoManager(clusterAddr)
	clusterKey, ok := clusterManager.ClusterKey()
	if !ok {
		logging.Get().Warn().Msg("get cluster key failed")
		return errors.Errorf("get cluster key failed.")
	}

	containerInfo, k8sInfo, podResInfo, podWatcher, err := initNodeInfos(hostName, hostIP, clusterKey)
	if err != nil {
		return err
	}
	//new flow session
	flow, err := netflow.NewFlowSession(containerInfo, k8sInfo, clusterManager, consoleAddr)
	if err != nil {
		return fmt.Errorf("Failed to initialize flow session, %w", err)
	}
	//free resource
	defer flow.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		flow.Start(ctx)
	}()

	// start events streaming
	if rtUdsAddr != "" {
		rtStream, err := initEventStreams(rtUdsAddr, hostName, clusterManager, mqWriter, containerInfo, podResInfo)
		if err != nil {
			return errors.Errorf("Failed to rt events streams, %v", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()
			if err = rtStream.Start(ctx); err != nil {
				logging.Get().Err(err).Msgf("runtime detection start error %v", err)
			}
		}()
	}

	// start dp service
	ciaEnabled := os.Getenv("CIA_ENABLED")
	if ciaEnabled == "1" {
		dpService, err := dp.NewDriftAssurance(podWatcher, podResInfo, mqWriter)
		if err != nil {
			logging.Get().Err(err).Msg("new drift assurance service failed")
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("drift service panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			if err = dpService.Start(ctx, consoleAddr); err != nil {
				logging.Get().Err(err).Msg("drift service start failed")
			}
		}()
	} else {
		logging.Get().Warn().Msg("not enable auto inject")
	}

	wg.Wait()

	return err
}

func main() {
	flag.Parse()

	if errs := loggingOptions.Validate(); len(errs) > 0 {
		logging.Get().Panic().Err(fmt.Errorf("%v", errs)).Msg("")
	}
	loggingOptions.SetConsoleWriterWrapper(logging.ConsoleCallerWriter)
	logging.ReplaceLogger(loggingOptions)

	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	err := Run(mainCtx)
	if err != nil {
		logging.Get().Error().Msgf("net init failed, %v.", err)
		mainCancel()
		os.Exit(1)
	}
}

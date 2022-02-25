package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/netflow"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/mqtools"
	"gitlab.com/security-rd/go-pkg/logging"
	_ "go.uber.org/automaxprocs"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const (
	// 定时上报，缓存的间隔和缓存大小，实现简单的频控
	defaultRTBuffInterval = 250 * time.Millisecond
	defaultRTBuffSize     = 100
)

func initEventStreams(udsAddr, nodeName string, cm *k8s.ClusterInfoManager, stanConn *mqtools.StanConn, dockerInfo *nodeinfo.DockerInfoManager, podResInfo *nodeinfo.PodResInfo) (*rtdetect.RuntimeEventStream, error) {
	bui := rtdetect.StreamBuilder(udsAddr, nodeName, cm)

	// add handlers here
	ecHandler, err := rtdetect.NewEcHandler(dockerInfo, podResInfo)
	if err != nil {
		return nil, err
	}
	// imHandler := rtdetect.NewImmuneHandler(stanConn)
	aeHandler := rtdetect.NewAssociatedEventsHandler(stanConn, dockerInfo)
	bui.WithHandler(rtdetect.NewAsyncHandler(ecHandler, defaultRTBuffInterval, defaultRTBuffSize))
	// bui.WithHandler(rtdetect.NewAsyncHandler(imHandler, defaultRTBuffInterval, defaultRTBuffSize))
	bui.WithHandler(rtdetect.NewSyncHandler(aeHandler))

	s, err := bui.Build(context.Background())
	return s, err
}

func initNodeInfos(hostName, hostIP string) (*nodeinfo.DockerInfoManager, *netflow.NodePodsInfo, *nodeinfo.PodResInfo, error) {
	dockerInfo, err := nodeinfo.NewDockerInfoManager(hostName, hostIP)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to initialize docker info manager : %w", err)
	}
	err = dockerInfo.Start()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("start dockerInfo listen failed, %v.", err)
	}

	k8sInfo := netflow.NewNodePodInfo(dockerInfo)
	podResInfo := nodeinfo.NewPodResInfo()
	podsWatcher := nodeinfo.NewNodePodsWatcher(hostName).AddWatcher(k8sInfo).AddWatcher(podResInfo).Build()
	err = podsWatcher.Start(context.Background())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("start pods watcher error: %v", err)
	}

	return dockerInfo, k8sInfo, podResInfo, nil
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

func NetInit(ctx context.Context) error {
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

	stanURL := os.Getenv("STAN_URL")
	if stanURL == "" {
		logging.Get().Warn().Msg("env STAN_URL not found")
		return errors.Errorf("get STAN address failed.")
	}
	stanClusterID := os.Getenv("STAN_CLUSTER_ID")
	if stanClusterID == "" {
		logging.Get().Warn().Msg("env STAN_CLUSTER_ID not found")
		stanClusterID = "tensorsec"
	}
	stanConn := mqtools.NewStanConn(func() (stan.Conn, error) {
		nc, err := nats.Connect(fmt.Sprintf("nats://%s", stanURL), nats.MaxReconnects(5), nats.ReconnectBufSize(64*1024), nats.ReconnectWait(500*time.Millisecond))
		if err != nil {
			return nil, err
		}
		stanConn, err := stan.Connect(stanClusterID, getClientID(hostName), stan.NatsConn(nc))
		return stanConn, err
	})

	clusterManager := k8s.NewClusterInfoManager(clusterAddr)

	dockerInfo, k8sInfo, podResInfo, err := initNodeInfos(hostName, hostIP)
	if err != nil {
		return err
	}
	//new flow session
	flow, err := netflow.NewFlowSession(dockerInfo, k8sInfo, clusterManager, consoleAddr)
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
		rtStream, err := initEventStreams(rtUdsAddr, hostName, clusterManager, stanConn, dockerInfo, podResInfo)
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

	wg.Wait()

	return err
}

func main() {

	flag.Parse()

	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	err := NetInit(mainCtx)
	if err != nil {
		logging.Get().Error().Msgf("net init failed, %v.", err)
		mainCancel()
		os.Exit(1)
	}
}

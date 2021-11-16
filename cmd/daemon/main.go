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
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/netflow/pkg/netflow"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/netflow/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/netflow/pkg/ruleMetrics"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/mqtools"
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

func initEventStreams(udsAddr, nodeName string, cm *k8s.ClusterInfoManager, stanConn *mqtools.StanConn) (*rtdetect.RuntimeEventStream, error) {
	bui := rtdetect.StreamBuilder(udsAddr, nodeName, cm)

	// add handlers here
	ecHandler, err := rtdetect.NewEcHandler()
	if err != nil {
		return nil, err
	}
	imHandler := rtdetect.NewImmuneHandler(stanConn)
	aeHandler := rtdetect.NewAssociatedEventsHandler(stanConn)
	bui.WithHandler(rtdetect.NewAsyncHandler(ecHandler, defaultRTBuffInterval, defaultRTBuffSize))
	bui.WithHandler(rtdetect.NewAsyncHandler(imHandler, defaultRTBuffInterval, defaultRTBuffSize))
	bui.WithHandler(rtdetect.NewSyncHandler(aeHandler))

	s, err := bui.Build(context.Background())
	return s, err
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
func NetInit(ctx context.Context) error {
	wg := sync.WaitGroup{}
	//get node name
	hostName := os.Getenv("MY_NODE_NAME")
	if hostName == "" {
		hostName = "Unknown"
	}
	podName := os.Getenv("MY_POD_NAME")
	if podName == "" {
		podName = "Unknown"
	}
	rtUdsAddr := os.Getenv("RTDETECT_UDS_ADDR")
	if rtUdsAddr == "" {
		logging.GetLogger().Warn().Msg("env RTDETECT_UDS_ADDR not found")
	}
	clusterAddr := os.Getenv("CLUSTER_ADDR")
	if clusterAddr == "" {
		logging.GetLogger().Warn().Msg("env CLUSTER_ADDR not found")
		return errors.Errorf("get cluster address failed.")
	}
	consoleAddr := os.Getenv("CONSOLE_ADDR")
	if consoleAddr == "" {
		logging.GetLogger().Warn().Msg("env CONSOLE_ADDR not found")
		return errors.Errorf("get console address failed.")
	}
	stanURL := os.Getenv("STAN_URL")
	if stanURL == "" {
		logging.GetLogger().Warn().Msg("env STAN_URL not found")
		return errors.Errorf("get STAN address failed.")
	}
	stanClusterID := os.Getenv("STAN_CLUSTER_ID")
	if stanClusterID == "" {
		logging.GetLogger().Warn().Msg("env STAN_CLUSTER_ID not found")
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

	ruleMetricsClient, err := ruleMetrics.NewRuleMetricsClient(hostName)
	if err != nil {
		//log.Warnf("Failed to initialize rule metrics client: %w", err)
	} else {
		ruleMetricsClient.Start()
	}
	//new k8s resource
	k8sResSync, err := netflow.NewK8sResourceSyncer()
	if err != nil {
		return fmt.Errorf("Failed to initialize k8s resource sycner, : %w", err)
	}
	//start k8s service
	err = k8sResSync.StartK8sServiceSyncer(ctx)
	if err != nil {
		return fmt.Errorf("listen k8s event failed, %v.", err)
	}
	//new flow session
	flow, err := netflow.NewFlowSession(k8sResSync, clusterManager)
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
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		flow.Start(ctx)
	}()

	// start events streaming
	if rtUdsAddr != "" {
		rtStream, err := initEventStreams(rtUdsAddr, hostName, clusterManager, stanConn)
		if err != nil {
			return fmt.Errorf("Failed to rt events streams, %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()
			if err = rtStream.Start(ctx); err != nil {
				logging.GetLogger().Err(err).Msgf("runtime detection start error %v", err)
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
		logging.GetLogger().Err(err).Msg("net init failed")
	}
}

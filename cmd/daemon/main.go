package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/netflow"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/ruleMetrics"
	"gitlab.com/piccolo_su/vegeta/pkg/clusters"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	_ "go.uber.org/automaxprocs"
)

const (
	// 定时上报，缓存的间隔和缓存大小，实现简单的频控
	defaultRTBuffInterval = 500 * time.Millisecond
	defaultRTBuffSize     = 500
)

func initEventStreams(udsAddr string, cm *clusters.Manager) (*rtdetect.RuntimeEventStream, error) {
	bui := rtdetect.StreamBuilder(udsAddr)

	// add handlers here
	ecHandler, err := rtdetect.NewEcHandler(cm)
	if err != nil {
		return nil, err
	}
	bui.WithHandler(rtdetect.NewAsyncHandler(ecHandler, defaultRTBuffInterval, defaultRTBuffSize))

	s, err := bui.Build(context.Background())
	return s, err
}
func NetInit(ctx context.Context) error {
	wg := sync.WaitGroup{}
	//get node name
	hostName := os.Getenv("MY_NODE_NAME")
	if hostName == "" {
		hostName = "Unknown"
	}
	rtUdsAddr := os.Getenv("RTDETECT_UDS_ADDR")
	if rtUdsAddr == "" {
		logging.GetLogger().Warn().Msg("env RTDETECT_UDS_ADDR not found")
	}
	clusterAddr := os.Getenv("CLUSTER_ADDR")
	if clusterAddr == "" {
		logging.GetLogger().Warn().Msg("env CLUSTER_ADDR not found")
		errors.Errorf("get cluster address failed.")
	}

	clusterManager := clusters.NewManager(clusterAddr)

	ruleMetricsClient, err := ruleMetrics.NewRuleMetricsClient(hostName)
	if err != nil {
		//log.Warnf("Failed to initialize rule metrics client: %w", err)
	} else {
		ruleMetricsClient.Start()
	}

	k8sResSync, err := netflow.NewK8sResourceSyncer()
	if err != nil {
		return fmt.Errorf("Failed to initialize k8s resource sycner, : %w", err)
	}
	err = k8sResSync.StartK8sServiceSyncer(ctx)
	if err != nil {
		return fmt.Errorf("listen k8s event failed, %v.", err)
	}

	flow, err := netflow.NewFlowSession(k8sResSync, clusterManager)
	if err != nil {
		return fmt.Errorf("Failed to initialize flow session, %w", err)
	}

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
		rtStream, err := initEventStreams(rtUdsAddr, clusterManager)
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
				err = fmt.Errorf("runtime detection start error %v", err)
			}
		}()
	}

	wg.Wait()

	return err
}

func main() {

	debug := flag.Bool("debug", false, "Run in debug mode with extended logging")

	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	err := NetInit(mainCtx)
	if err != nil {
		log.Errorf("net init failed, %v.", err)
	}
}

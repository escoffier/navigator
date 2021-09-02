package main

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/netflow"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/ruleMetrics"
)

func GetClusterId() (string, error) {
	clusterAddr := os.Getenv("CLUSTER_ADDR")
	if clusterAddr == "" {
		return "", errors.Errorf("get cluster address failed.")
	}

	clusterUrl := fmt.Sprintf("%s/internal/cluster", clusterAddr)

	for i := 0; i < 20; i++ {
		clusterId, err := netflow.GetK8sClusterInfo(clusterUrl)
		if err == nil && len(clusterId) > 0 {
			return clusterId, nil
		}

		time.Sleep(5 * time.Second)
	}

	return "", errors.Errorf("get k8s cluster id failed with timeout")
}

func NetInit() error {
	//get node name
	hostName := os.Getenv("MY_NODE_NAME")
	if hostName == "" {
		hostName = "Unknown"
	}
	//get cluster id
	clusterId, err := GetClusterId()
	if err != nil {
		return err
	}

	ruleMetricsClient, err := ruleMetrics.NewRuleMetricsClient(hostName)
	if err != nil {
		log.Warnf("Failed to initialize rule metrics client: %w", err)
	} else {
		ruleMetricsClient.Start()
	}

	k8sResSync, err := netflow.NewK8sResourceSyncer()
	if err != nil {
		return fmt.Errorf("Failed to initialize k8s resource sycner, : %w", err)
	}

	err = k8sResSync.StartK8sServiceSyncer()
	if err != nil {
		return fmt.Errorf("listen k8s event failed, %v.", err)
	}

	flow, err := netflow.NewFlowSession(k8sResSync, clusterId)
	if err != nil {
		return fmt.Errorf("Failed to initialize flow session, %w", err)
	}

	stopCron := make(chan struct{})

	flow.Start(stopCron)

	close(stopCron)

	return nil
}

func main() {

	debug := flag.Bool("debug", false, "Run in debug mode with extended logging")

	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	err := NetInit()
	if err != nil {
		log.Errorf("net init failed, %v.", err)
	}
}

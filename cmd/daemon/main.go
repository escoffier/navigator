package main

import (
	"context"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/learn"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/memshell"
	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo/handler"
	svcdiscovery "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo/svc-discovery"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/waf"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/status"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	flag "github.com/spf13/pflag"
	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/cmap"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/degrade"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/holmes"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/microseg"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/netflow"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/rscan"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mozart"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var loggingOptions *logging.Options

func init() {
	rand.Seed(time.Now().UnixNano())

	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.Level = int(zerolog.TraceLevel)
	loggingOptions.AddFlags(flag.CommandLine)
}

const (
	// 定时上报，缓存的间隔和缓存大小，实现简单的频控
	defaultRTBuffInterval = 250 * time.Millisecond
	defaultRTBuffSize     = 100
)

func WaitSignal(stop chan struct{}) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	close(stop)
}

func initEventStreams(udsAddr, nodeName, myNamespace, ctrlURL, ruleDirPath string, cm *k8s.ClusterInfoManager, containerInfo nodeinfo.ContainerInfoManager, podResInfo *nodeinfo.PodResInfo, palaceHandler *palace.Palace, mozartEngine *mozart.Engine) (*holmes.EngineStreamHandler, error) {
	config := holmes.NewEngineStreamConfig()
	config.WithCtrlServerURL(ctrlURL).WithMyNodeName(nodeName).WithRulesDirPath(ruleDirPath).WithUnixSocketPath(udsAddr).WithMyNamespace(myNamespace)
	handler := holmes.NewEventsStreamHandler(config, cm, containerInfo, podResInfo, palaceHandler, mozartEngine)
	return handler, nil
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

func initNodeInfos(rc *netflow.RedisClient, hostName, hostIP, clusterKey, myNamespace string, stop <-chan struct{}) (nodeinfo.ContainerInfoManager, *netflow.NodePodsInfo, *nodeinfo.PodResInfo, *nodeinfo.NodePodsWatcher, string, error) {
	kubeClient, err := K8sClient()
	if err != nil {
		return nil, nil, nil, nil, "", errors.Errorf("k8s client init failed, %v", err)

	}
	nodePodWatcher := nodeinfo.NewNodePodsWatcher(hostName, clusterKey, kubeClient)
	nodePodWatcher.Build()
	if err != nil {
		return nil, nil, nil, nil, "", errors.Errorf("k8s client init failed, %v", err)
	}

	cmWatcher := cmap.NewWatcher(kubeClient, myNamespace, "ivan-degradation-controller").AddFunc(degrade.DegradationCmapWatcher).Build()
	_ = cmWatcher.Start()

	containerType, err := nodePodWatcher.Build().GetContainerType()
	if err != nil {
		return nil, nil, nil, nil, "", errors.Errorf("get k8s node containerRuntimeVersion failed, %v", err)
	}

	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		return nil, nil, nil, nil, "", errors.Errorf("get mq writer failed, %v", err)
	}

	agent := containerassets.NewAgent(mqWriter)
	podResInfo := nodeinfo.NewPodResInfo(agent, clusterKey)
	k8sInfo := netflow.NewNodePodInfo(rc, kubeClient)

	var containerInfo nodeinfo.ContainerInfoManager
	switch containerType {
	case nodeinfo.DockerType:
		containerInfo, err = nodeinfo.NewDockerInfoManager(clusterKey, hostName, hostIP, agent)
		if err != nil {
			return nil, nil, nil, nil, "", errors.Errorf("Failed to initialize docker info manager, %v", err)
		}
		logging.Get().Info().Msgf("new docker client success!")
	case nodeinfo.CrioType:
		containerInfo, err = nodeinfo.NewCRIOInfoManager(clusterKey, hostName, hostIP, agent)
		if err != nil {
			return nil, nil, nil, nil, "", errors.Errorf("Failed to initialize cri-o info manager, %v", err)
		}
		logging.Get().Info().Msgf("new cri-o client success!")
	case nodeinfo.PodmanType:
		containerInfo, err = nodeinfo.NewPodmanInfoManager()
		if err != nil {
			return nil, nil, nil, nil, "", errors.Errorf("Failed to initialize podman info manager, %v", err)
		}
		logging.Get().Info().Msgf("new podman client success!")
	case nodeinfo.ContainerdType:
		containerInfo, err = nodeinfo.NewContainerdInfoManager(clusterKey, hostName, hostIP, agent)
		if err != nil {
			return nil, nil, nil, nil, "", errors.Errorf("Failed to initialize containerd info manager, %v", err)
		}
		logging.Get().Info().Msgf("new containerd client success!")
	}
	discoveryHandler := svcdiscovery.NewDiscoveryHandler("/host", containerInfo.RunCmd)
	k8sInfo.SetContainerManager(containerInfo)
	containerInfo.AddEventHandler(nodeinfo.ContainerEventHandlerFuncs{
		AddFunc: func(object interface{}) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			container, ok := object.(*model.TensorRawContainer)
			if !ok {
				return
			}
			assetsContainer := &assets.TensorRawContainer{
				TensorRawContainer: container,
				Discovery:          &assets.TensorRawContainerDiscovery{},
			}
			// 服务识别
			if container.Pid > 0 {
				logging.Get().Info().Msgf("discovery pid:%d", container.Pid)
				frameworkInfos, svcInfos, err := discoveryHandler.Discovery(container.ContainerID, strconv.Itoa(container.Pid), container.Path)
				if err != nil {
					logging.Get().Err(err).Msgf("discovery rawContainer failed ,containerName:%s ,pid:%d", container.Name, container.Pid)
				}
				if len(frameworkInfos) > 0 || len(svcInfos) > 0 {
					logging.Get().Err(err).Msgf("discovery  containerName:%s result. frameworkInfos:%d, svcInfos:%d", container.Name, len(frameworkInfos), len(svcInfos))
				}
				assetsContainer.Discovery.Frameworks = frameworkInfos
				assetsContainer.Discovery.Services = svcInfos
			}
			if (!container.K8sManaged) && (container.IP != "" || container.IPV6 != "") {
				ip := container.IP
				if container.IPV6 != "" {
					ip = container.IPV6
				}
				k8sInfo.SaveContainerData(ip, container.ContainerID, &daemon.ContainerData{
					ContainerName: container.Name,
					ContainerPid:  container.Pid,
				})
			}
			agent.HandlerContainerEvent(ctx, clusterKey, assets.ActionAdd, assetsContainer)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
			defer cancel()

			logging.Get().Info().Msgf("handle event %+v", newObj)
			container, ok := newObj.(*model.TensorRawContainer)
			if !ok {
				return
			}

			if (!container.K8sManaged) && (container.IP != "" || container.IPV6 != "") {
				ip := container.IP
				if container.IPV6 != "" {
					ip = container.IPV6
				}
				k8sInfo.SaveContainerData(ip, container.ContainerID, &daemon.ContainerData{
					ContainerName: container.Name,
					ContainerPid:  container.Pid,
				})
			}
			final := &assets.TensorRawContainer{
				TensorRawContainer: container,
			}
			agent.HandlerContainerEvent(ctx, clusterKey, assets.ActionUpdate, final)
		},
		DeleteFunc: func(obj interface{}) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
			defer cancel()

			container, ok := obj.(*model.TensorRawContainer)
			if !ok {
				return
			}

			if (!container.K8sManaged) && (container.IP != "" || container.IPV6 != "") {
				ip := container.IP
				if container.IPV6 != "" {
					ip = container.IPV6
				}
				k8sInfo.DeleteResData(ip)
			}
			logging.Get().Debug().Msgf("delete container: %s, action %v", container.ContainerID, assets.ActionDelete)
			final := &assets.TensorRawContainer{
				TensorRawContainer: container,
			}
			agent.HandlerContainerEvent(ctx, clusterKey, assets.ActionDelete, final)
		},
	})

	// podsWatcher := nodePods.AddWatcher(k8sInfo).AddWatcher(podResInfo).Build()
	podsWatcher := nodePodWatcher.AddEventHandler(nodeinfo.PodEventHandlerFuncs{
		AddFunc:    podResInfo.OnAdd,
		UpdateFunc: podResInfo.OnUpdate,
		DeleteFunc: podResInfo.OnDelete,
	}).AddEventHandler(nodeinfo.PodEventHandlerFuncs{
		AddFunc:    k8sInfo.OnAdd,
		UpdateFunc: k8sInfo.OnUpdate,
		DeleteFunc: k8sInfo.OnDelete,
	}).Build()
	err = podsWatcher.Start(context.Background(), stop)
	if err != nil {
		return nil, nil, nil, nil, "", fmt.Errorf("start pods watcher error: %v", err)
	}

	containerInfo.SetPodStore(podsWatcher)
	err = containerInfo.Start()
	if err != nil {
		return nil, nil, nil, nil, "", fmt.Errorf("start dockerInfo listen failed, %v.", err)
	}
	return containerInfo, k8sInfo, podResInfo, podsWatcher, containerType, nil
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

func Run(ctx context.Context, stopCh chan struct{}) error {
	logging.Get().Info().Msg("start initing")

	wg := sync.WaitGroup{}
	// get local env
	hostName, hostIP := GetEnvInfo()
	// get rt uds addr
	rtUdsAddr := os.Getenv("RTDETECT_UDS_ADDR")
	if rtUdsAddr == "" {
		logging.Get().Warn().Msg("env RTDETECT_UDS_ADDR not found")
	}
	rulesDirPath := os.Getenv("RTDETECT_RULES_DIR")
	if rulesDirPath == "" {
		rulesDirPath = "/var/run/holmes-engine/rules/"
	}
	clusterAddr := os.Getenv("CLUSTER_MANAGER_URL")
	if clusterAddr == "" {
		logging.Get().Warn().Msg("env CLUSTER_MANAGER_URL not found")
		return errors.Errorf("get cluster address failed.")
	}
	// get console address
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
	clusterGrpcAddr := os.Getenv("CLUSTER_MANAGER_GRPC_ADDR")
	if clusterAddr == "" {
		logging.Get().Warn().Msg("env CLUSTER_MANAGER_GRPC_ADDR not found")
		return errors.Errorf("get cluster grpc address failed.")
	}

	workNamespace := os.Getenv("MY_POD_NAMESPACE")

	mqFactory := mq.GetClientFactory()
	mqWriter, err := mqFactory.Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("Init mq error")
	} else {
		logging.Get().Info().Msg("Init mq done")
	}

	nodeKey := fmt.Sprintf("%s-daemon", os.Getenv("MY_NODE_NAME"))
	rpcStream := rpcstream.NewStreamFactory(rpcstream.WithClusterKey(nodeKey)).Client(clusterGrpcAddr)
	_ = rpcStream.AddHandler(&pb.ComplianceScanReq{}, &scapper.ScanHandler{Writer: mqWriter})
	_ = rpcStream.AddHandler(&pb.NodeLoadReq{}, &handler.NodeLoadHandler{})
	rpcStream.Start()

	kubeConfig, err := k8s.KubeConfig()
	if err != nil {
		return nil
	}
	clientset, err := assets.NewForConfig(kubeConfig)
	if err != nil {
		return nil
	}

	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 10*time.Hour, informers.WithNamespace(workNamespace))

	clusterManager := k8s.NewClusterInfoManagerWithOpts(clusterAddr, clientset, factory, workNamespace)
	clusterKey, ok := clusterManager.ClusterKey()
	if !ok {
		logging.Get().Warn().Msg("get cluster key failed")
		return errors.Errorf("get cluster key failed.")
	}
	logging.Get().Info().Msg("Init cluster manager done")

	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	if myNamespace == "" {
		myNamespace = "tensorsec"
	}

	export := os.Getenv("EXPORTRAWCONTAINER")
	if export == "false" {
		nodeinfo.ExportRawContainer = false
	}

	rc, err := netflow.NewRedisClient()
	if err != nil {
		return fmt.Errorf("redis client init failed, %+v", err)
	}

	containerInfo, k8sInfo, podResInfo, podWatcher, containerType, err := initNodeInfos(rc, hostName, hostIP, clusterKey, myNamespace, stopCh)
	if err != nil {
		return err
	}

	logging.Get().Info().Msg("Init NodeInfo done")

	// new flow session
	flow, err := netflow.NewFlowSession(rc, k8sInfo, containerInfo, clusterManager, consoleAddr, clusterManager)
	if err != nil {
		return fmt.Errorf("Failed to initialize flow session, %w", err)
	}
	logging.Get().Info().Msg("Init netflows done")

	// free resource
	defer flow.Close()

	// microseg and waf
	var agentClient, agentEventClient *heavyagent.Client
	pathExists := false
	if err != nil {
		if os.IsNotExist(err) {
			err = os.Mkdir("/var/run/heavy-agent", fs.ModeDir)
			if err != nil {
				logging.Get().Err(err).Msg("create dir: /var/run/heavy-agent/")
			} else {
				pathExists = true
			}
		}
	} else {
		pathExists = true
	}

	if pathExists {
		agentClient, err = heavyagent.NewClient("127.0.0.1:9999")
		if err != nil {
			return err
		}

		agentEventClient, err = heavyagent.NewClient("127.0.0.1:8888")
		if err != nil {
			return err
		}
	}

	stopChan := make(chan struct{})
	policyClient := microseg.NewPolicyClient(agentClient)
	if agentClient == nil {
		logging.Get().Error().Msg("agentClient is nil")
	}
	controller := nodeinfo.NewPodController(podWatcher.PodLister(), podWatcher.PodInformer(), containerInfo, policyClient)
	go controller.Run(stopChan)

	tensorFactory := externalversions.NewSharedInformerFactoryWithOptions(clientset.TensorClientset, 10*time.Hour,
		externalversions.WithTweakListOptions(func(lo *v1.ListOptions) {
			lo.LabelSelector = fmt.Sprintf("kubernetes.io/node-name=%s", hostName)
		}))
	ruleController := microseg.NewRuleGroupController(clientset.TensorClientset, tensorFactory, policyClient, hostName, mqWriter, agentClient)

	go ruleController.Run(stopChan)

	var wafEnabled = true
	wafEnv := os.Getenv("WAF")
	if wafEnv == "true" {
		wafEnabled = true
	}
	if wafEnabled {
		wafClient := waf.NewWafClient(agentClient)
		wafController := waf.NewWafController(clientset.TensorClientset, factory, tensorFactory, podWatcher, wafClient)
		go wafController.Run(stopCh)
	}

	tensorFactory.Start(stopChan)
	tensorFactory.WaitForCacheSync(stopChan)

	clusterManagerSvc := os.Getenv("CLUSTER_MANAGER_URL")
	eventProcessor := heavyagent.NewEventProcessor(clusterManagerSvc, agentEventClient)

	microsegHandler := microseg.NewHandler(clusterManagerSvc)
	eventProcessor.AddHandler("microseg", microsegHandler)

	wafhander := waf.NewHandler(clusterManagerSvc)
	eventProcessor.AddHandler("waf", wafhander)

	go eventProcessor.Run1()

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
		palaceHandler, err := palace.Init()
		if err != nil {
			logging.Get().Err(err).Msgf("Failed to init palaceHandler, %v", err)
			return errors.Errorf("Failed to init palaceHandler, %v", err)
		} else {
			logging.Get().Info().Msg("Init palace done")
		}

		redisClient, err := cache.NewRedis()
		if err != nil {
			logging.Get().Err(err).Msgf("Failed to init redis, %v", err)
			return errors.Errorf("Failed to init redis, %v", err)
		}

		mozartEngine, err := mozart.NewMozartEngine(ctx,
			mozart.SetPalace(&palaceHandler),
			mozart.SetClusterManager(clusterManager),
			mozart.SetPrInfo(podResInfo),
			mozart.SetRedis(redisClient),
		)
		if err != nil {
			logging.Get().Err(err).Msgf("Failed to init mozartEngine, %v", err)
			return errors.Errorf("Failed to init mozartEngine, %v", err)
		}

		rtStream, err := initEventStreams(rtUdsAddr, hostName, myNamespace, clusterAddr, rulesDirPath, clusterManager, containerInfo, podResInfo, &palaceHandler, mozartEngine)

		if err != nil {
			return errors.Errorf("Failed to rt events streams, %v", err)
		} else {
			logging.Get().Info().Msg("Init event streams done")
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()
			err := rtStream.StartToHandle(context.Background())
			if err != nil {
				logging.Get().Err(err).Msg("handler error")
			}
		}()
	}

	// start dp service
	ciaEnabled := os.Getenv("CIA_ENABLED")
	if ciaEnabled == "1" {
		clusterName, _ := clusterManager.ClusterName()

		palaceHandler, err := palace.Init()
		if err != nil {
			logging.Get().Err(err).Msgf("Failed to init palaceHandler, %v", err)
			return errors.Errorf("Failed to init palaceHandler, %v", err)
		} else {
			logging.Get().Info().Msg("Init palace done")
		}

		dpService, err := dp.NewDriftAssurance(podWatcher, podResInfo, mqWriter, consoleAddr,
			clusterName, clusterKey, containerType, &palaceHandler, clusterManager)
		if err != nil {
			logging.Get().Err(err).Msg("new drift assurance service failed")
			return err
		} else {
			logging.Get().Info().Msg("Init drift done")
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("drift service panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			if err = dpService.Start(ctx); err != nil {
				logging.Get().Err(err).Msg("drift service start failed")
			}
		}()
	} else {
		logging.Get().Warn().Msg("not enable auto inject")
	}

	// start runtime scan
	rsEnabled := os.Getenv("RSCAN_ENABLED")
	if rsEnabled == "1" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("runtime scan panic: %v.stack:%s", r, debug.Stack())
				}
			}()

			rsScanner, err := rscan.NewRuntimeScanner(
				rscan.WithPodResInfo(podResInfo),
				rscan.WithNodePodResInfo(podWatcher),
				rscan.WithClusterInfoManager(clusterManager),
				rscan.WithMaxUserWatches(rscan.DefaultMaxUserWatches),
				rscan.WithConcurrentScanNum(rscan.DefaultConcurrentScanNum))
			if err != nil {
				logging.Get().Err(err).Msg("failed to create runtime scanner")
				return
			}
			if err = rsScanner.Run(); err != nil {
				logging.Get().Err(err).Msg("runtime scanner run err")
			}
		}()
	}

	// start cis checker
	cisEnabled := os.Getenv("CIS_ENABLED")
	if cisEnabled == "1" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("cis checker panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			cisChecker, err := cis.NewCisController(
				cis.WithPodResInfo(podResInfo),
				cis.WithNodePodResInfo(podWatcher),
				cis.WithClusterInfoManager(clusterManager),
			)
			if err != nil {
				logging.Get().Err(err).Msg("new cis checker failed")
				return
			}
			if err = cisChecker.Start(ctx); err != nil {
				logging.Get().Err(err).Msg("cis checker start failed")
			}
		}()
	}

	memshellEnabled := os.Getenv("MEMSHELL_ENABLED")
	if memshellEnabled == "1" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("memshell checker panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			memShellHandler, err := memshell.NewMemShell(
				memshell.WithNodePodResInfo(podWatcher),
				memshell.WithClusterInfoManager(clusterManager),
				memshell.WithPodResInfo(podResInfo),
			)
			if err != nil {
				logging.Get().Err(err).Msg("new memshell checker failed")
				return
			}
			if err = memShellHandler.Start(ctx); err != nil {
				logging.Get().Err(err).Msg("memshell checker start failed")
			}

		}()
	}

	// behavior learning
	blEnabled := os.Getenv("BL_ENABLED")
	if blEnabled == "1" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("behavior learning panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			bl, err := learn.New(
				learn.WithClusterInfoManager(clusterManager),
				learn.WithPodResInfo(podResInfo),
				learn.WithNodePodResInfo(podWatcher),
				learn.WithMq(mqWriter),
			)

			if err != nil {
				logging.Get().Err(err).Msg("new behavior learning failed")
				return
			}
			if err = bl.Run(ctx); err != nil {
				logging.Get().Err(err).Msg("behavior learning start failed")
			}
		}()
	}

	go func() {
		srv := status.NewServer(12000, agentClient)
		srv.Run()
	}()
	WaitSignal(stopCh)
	wg.Wait()
	return err
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
func main() {
	flag.Parse()

	if errs := loggingOptions.Validate(); len(errs) > 0 {
		logging.Get().Panic().Err(fmt.Errorf("%v", errs)).Msg("")
	}
	loggingOptions.SetConsoleWriterWrapper(logging.ConsoleCallerWriter)
	logging.ReplaceLogger(loggingOptions)

	setLoggingLevel()

	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	util.InitPprofMontitor()

	stopCh := make(chan struct{})
	err := Run(mainCtx, stopCh)
	if err != nil {
		logging.Get().Err(err).Msg("failed to run daemon.")
		os.Exit(1)
	}
}

package dp

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

var defaultDockerSocket string = "unix:///host/var/run/docker.sock"

const (
	defaultConcurrentNum = 5
)

type DriftAssurance struct {
	config     *ConfigManager
	injector   *Injector
	judge      *ExecJudge
	subscriber *Subscriber
	podResInfo *nodeinfo.PodResInfo
	rt         container.Runtime
	wc         *whitelist.WhitelistCount
}

func (d *DriftAssurance) GetConfigManager() *ConfigManager {
	return d.config
}

func (d *DriftAssurance) Start(ctx context.Context) error {

	wg := sync.WaitGroup{}

	// config manager: sync white list
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("config manager panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		_ = d.config.Start()
		logging.Get().Error().Msg("config manager exit")
	}()

	// judge: receive container's dp.so request, response file-can-exec result
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("judge panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		err := d.judge.Start()
		logging.Get().Err(err).Msg("judge exit")
	}()

	// sub events: receive runtime event and inject to container
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("subscriber panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		err := d.rt.MonitorEvent(d.subscriber.RuntimeEventCallBack(d.config, d.rt, d.wc, d.injector))
		logging.Get().Err(err).Msg("monitor event exit")
	}()

	containers, err := d.rt.ListRunningContainers()
	if err != nil {
		logging.Get().Error().Msg("get running containers fail")
	}
	for _, c := range containers {
		cm, err := d.rt.GetContainerMeta(c.ID)
		if err != nil {
			logging.Get().Error().Msgf("get container meta fail, containerId: %s\n", c.ID)
		}
		for _, imageDigest := range cm.ImageDigest {
			d.config.AddImageUsed(imageDigest)
		}
	}
	// get running images whitelist
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("get running container image result panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		initRunningContainerImagesWhiteList(d.rt, d.config, d.wc)
	}()

	// first inject all containers
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("inject exist containers panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		firstInjectContainer(d.rt, d.injector)
	}()

	logging.Get().Debug().Msg("dp service running")
	wg.Wait()
	return nil
}

func NewDriftAssurance(podWatcher *nodeinfo.NodePodsWatcher, podResInfo *nodeinfo.PodResInfo, mqWriter mq.Writer, consoleAddr, clusterName, clusterKey string, palaceHandler *palace.Palace) (*DriftAssurance, error) {
	d := &DriftAssurance{}

	rt, err := createRuntimeCli()
	if err != nil {
		logging.Get().Err(err).Msg("drift assurance create runtime failed")
		return nil, err
	}
	d.rt = rt

	cm, err := NewConfigManger(consoleAddr, clusterKey)
	if err != nil {
		logging.Get().Err(err).Msg("create config manager failed")
		return nil, fmt.Errorf("create config manager failed:%v", err)
	}
	d.config = cm

	j, err := NewExecJudge("", cm, rt, podWatcher, podResInfo, mqWriter, clusterName, palaceHandler)
	if err != nil {
		logging.Get().Err(err).Msg("create exec judge failed")
		return nil, fmt.Errorf("create exec judge failed:%v", err)
	}
	d.judge = j

	s, err := NewSubscriber()
	if err != nil {
		logging.Get().Err(err).Msg("create subscriber failed")
		return nil, fmt.Errorf("create subscriber failed:%v", err)
	}
	d.subscriber = s

	d.podResInfo = podResInfo

	// init Injector
	d.injector, err = NewInjector(podWatcher, podResInfo, mqWriter)
	if err != nil {
		logging.Get().Err(err).Msg("create injector failed")
		return nil, err
	}

	d.wc = whitelist.NewWhitelistHandler()

	return d, nil
}

func isUnixSockFile(filename string) bool {
	if strings.HasPrefix(filename, "unix://") {
		filename = filename[len("unix://"):]
	}

	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeSocket) != 0
}

func unixSockFileFromAddr(addr string) string {
	filename := addr
	if strings.HasPrefix(addr, "unix://") {
		filename = addr[len("unix://"):]
	}
	return filename
}

func createRuntimeCli() (container.Runtime, error) {
	var rt container.Runtime
	var err error
	dockerHost := os.Getenv("DOCKER_SOCKET_ADDR")
	if dockerHost == "" {
		dockerHost = defaultDockerSocket
	}
	if isUnixSockFile(dockerHost) {
		rt, err = container.Open(container.RuntimeConfig{Type: "docker"})
		if err != nil {
			return nil, err
		}
	} else {
		// todo: support containerd or cri-o unix socket
		return nil, fmt.Errorf("not valid runtime socket")
	}
	return rt, nil
}

func initRunningContainerImagesWhiteList(rt container.Runtime, config *ConfigManager, wc *whitelist.WhitelistCount) error {
	imageScanStart := time.Now()
	scannedCount := 0

	containers, err := rt.ListRunningContainers()
	if err != nil {
		return err
	}
	concurrentNum := os.Getenv("CONCURRENT_NUM")
	concurrentNumInt := defaultConcurrentNum
	if concurrentNum != "" {
		concurrentNumInt, err = strconv.Atoi(concurrentNum)
		if err != nil {
			logging.Get().Err(err).Msg("get concurrent num failed")
			concurrentNumInt = defaultConcurrentNum
		}
	}
	logging.Get().Debug().Msgf("concurrent num: %d", concurrentNumInt)

	var wg sync.WaitGroup
	ch := make(chan struct{}, concurrentNumInt)

	for _, c := range containers {
		wg.Add(1)
		ch <- struct{}{}
		go func(c types.Container) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("init running container images white list panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			defer func() {
				<-ch
			}()
			cm, err := rt.GetContainerMeta(c.ID)
			if err != nil {
				logging.Get().Err(err).Str("containerID", c.ID).Msg("get container meta failed")
				return
			}
			digests := cm.ImageDigest
			if _, skip := config.IsImageDigestsExist(digests); skip {
				return
			}
			for _, d := range digests {
				err = config.SetWhiteListScanning(d)
				if err != nil {
					logging.Get().Err(err).Msgf("imageDigest: %v", d)
				}
			}

			imageInspect, err := rt.GetImageInspect(c.ImageID)
			if err != nil {
				logging.Get().Err(err).Str("imageID", c.ImageID).Msg("get image inspect failed")
				return
			}
			imageInfo, err := wc.MakeWhiteListByOverLay(imageInspect)
			scannedCount++
			if err != nil {
				logging.Get().Err(err).Str("imageID", c.ImageID).Msg("make whitelist failed")
				return
			}
			for _, v := range digests {
				config.SetContainerWhiteList(v, imageInfo.WhiteList)
				_ = config.SetWhiteListReady(v)
			}
			logging.Get().Debug().Msgf("get container meta: %+v\n", cm)
		}(c)
	}
	logging.Get().Info().Msgf("image scan time: %v, num: %v, hashtablesize: %v whitelist dirs num: %v, dir hitcount: %v",
		time.Since(imageScanStart), scannedCount, len(config.execWhiteList), wc.ImageDirCount, wc.HitCount)
	wc.CleanWhiteListCount()
	wg.Wait()
	return nil
}

func firstInjectContainer(rt container.Runtime, injector *Injector) error {
	injectStartTime := time.Now()
	injectCount := 0
	wantInjectCount := 0

	containers, err := rt.ListRunningContainers()
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return fmt.Errorf("no running container")
	}

	for _, c := range containers {
		cm, err := rt.GetContainerMeta(c.ID)
		if err != nil {
			logging.Get().Err(err).Str("containerID", c.ID).Msg("get container meta failed")
			continue
		}
		injected, err := injector.DoInject(cm)
		if err != nil {
			// logging.Get().Err(err).Str("containerID", c.ID).Msg("inject container failed")
		}
		if injected {
			injectCount++
		}
		wantInjectCount++

	}
	logging.Get().Info().Msgf("inject time: %v, want: %v, actual num: %v", time.Since(injectStartTime), wantInjectCount, injectCount)
	return nil
}

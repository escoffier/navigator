package dp

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/image"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

const defaultDockerSocket string = "unix:///var/run/docker.sock"

type DriftAssurance struct {
	config     *ConfigManager
	injector   *Injector
	judge      *ExecJudge
	subscriber *Subscriber
	podResInfo *nodeinfo.PodResInfo
	rt         container.Runtime
}

func (d *DriftAssurance) GetConfigManager() *ConfigManager {
	return d.config
}

func (d *DriftAssurance) Start(ctx context.Context, consoleAddr string) error {
	// set log level
	logging.SetVerbose()

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
		d.config.consoleAddr = consoleAddr
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
		err := d.rt.MonitorEvent(d.subscriber.RuntimeEventCallBack(d))
		logging.Get().Err(err).Msg("monitor event exit")
	}()

	//get running image result
	wg.Add(1)
	go func() {
		imageScanStart := time.Now()
		defer wg.Done()
		scannedCount := 0
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("get running container image result panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		containers, err := d.rt.ListRunningContainers()
		if err != nil {
			logging.Get().Err(err).Msg("get running container image result failed")
			return
		}

		for _, i := range containers {
			imageInspect, err := d.rt.GetImageInspect(i.ImageID)
			if err != nil {
				logging.Get().Err(err).Msg("get image inspect failed")
				continue
			}
			skip := false
			for _, v := range imageInspect.RepoDigests {
				arr := strings.Split(v, "@")
				if len(arr) != 2 {
					logging.Get().Warn().Str("repoDigest", v).Msg("wrong format,ignore")
					continue
				}
				tmpDigest := arr[1]
				if d.config.execWhiteList[tmpDigest] != nil {
					skip = true
				}
				d.config.AddImageUsed(tmpDigest)
			}
			if skip {
				continue
			}
			imageInfo, err := image.MakeWhiteListByOverLay(imageInspect)
			scannedCount++
			if err != nil {
				logging.Get().Err(err).Msg("make whitelist failed")
				continue
			}
			for _, v := range imageInspect.RepoDigests {
				arr := strings.Split(v, "@")
				if len(arr) != 2 {
					logging.Get().Warn().Str("repoDigest", v).Msg("wrong format,ignore")
					continue
				}
				tmpDigest := arr[1]
				d.config.SetContainerWhiteList(tmpDigest, imageInfo.WhiteList)
			}

		}
		logging.Get().Info().Msgf("image scan time: %v, num: %v, hashtablesize: %v",
			time.Since(imageScanStart), scannedCount, len(d.config.execWhiteList))
	}()

	// first inject all containers
	wg.Add(1)
	go func() {
		injectStartTime := time.Now()
		defer wg.Done()
		injectCount := 0
		wantInjectCount := 0
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("inject exist containers panic: %v.stack:%s", r, debug.Stack())
			}
		}()

		containers, err := d.rt.ListRunningContainers()
		if err != nil {
			logging.Get().Err(err).Msg("list running containers failed")
			return
		}
		// logging.Get().Debug().Msgf("list running containers: %v\n", containers)

		for _, c := range containers {
			cm, err := d.rt.GetContainerMeta(c.ID)
			if err != nil {
				logging.Get().Err(err).Str("containerID", c.ID).Msg("get container meta failed,bypass inject")
				continue
			}
			logging.Get().Debug().Msgf("get container meta: %+v\n", cm)

			injected, err := d.injector.DoInject(cm)
			if err != nil {
				// just log,continue inject other container
				logging.Get().Err(err).Str("containerID", c.ID).Msg("inject container failed")
			}
			if injected {
				injectCount++
			}
			wantInjectCount++
		}
		logging.Get().Info().Msgf("inject time: %v, want: %v, actual num: %v", time.Since(injectStartTime), wantInjectCount, injectCount)

		logging.Get().Info().Msg("inject containers finished")
	}()

	logging.Get().Debug().Msg("dp service running")
	wg.Wait()
	return nil
}

func NewDriftAssurance(podWatcher *nodeinfo.NodePodsWatcher, podResInfo *nodeinfo.PodResInfo, mqWriter mq.Writer) (*DriftAssurance, error) {
	d := &DriftAssurance{}

	rt, err := createRuntimeCli()
	if err != nil {
		logging.Get().Err(err).Msg("drift assurance create runtime failed")
		return nil, err
	}
	d.rt = rt

	cm, err := NewConfigManger()
	if err != nil {
		logging.Get().Err(err).Msg("create config manager failed")
		return nil, fmt.Errorf("create config manager failed:%v", err)
	}
	d.config = cm

	j, err := NewExecJudge("", cm, rt, podWatcher, podResInfo, mqWriter)
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
	d.injector, err = NewInjector(podWatcher)
	if err != nil {
		logging.Get().Err(err).Msg("create injector failed")
		return nil, err
	}

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
	if isUnixSockFile(defaultDockerSocket) {
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

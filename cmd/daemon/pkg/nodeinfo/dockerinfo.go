package nodeinfo

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
)

const (
	containerIDTimeoutSec = int64(90)
)

type DockerInfoManager struct {
	dockerCli     *client.Client
	hostIP        string
	hostName      string
	containerData map[string]int64 // map[containerId]time

	sync.RWMutex
}

func NewDockerInfoManager(hostName, hostIP string) (*DockerInfoManager, error) {
	//docker client
	dockerCli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, errors.Errorf("docker new client failed, %v", err)
	}

	rs := DockerInfoManager{
		dockerCli:     dockerCli,
		hostIP:        hostIP,
		hostName:      hostName,
		containerData: make(map[string]int64, 30),
	}
	go rs.clearContainerTimeoutData()

	return &rs, nil
}

func (d *DockerInfoManager) clearContainerTimeoutData() {
	ticker := time.NewTicker(30 * time.Second)
	count := 0
	for now := range ticker.C {
		func(nowTime time.Time) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()

			d.Lock()
			defer d.Unlock()

			if count >= 60 { // if a map keeps a stable size but is with continouous add or delete, it should be reconstructed after a period of time to prevent memory leak
				newMap := make(map[string]int64, len(d.containerData))
				for containerID, timestamp := range d.containerData {
					if nowTime.Unix()-timestamp >= containerIDTimeoutSec {
						continue
					}
					newMap[containerID] = timestamp
				}
				d.containerData = newMap
				count = 0
			} else {
				for containerID, timestamp := range d.containerData {
					if nowTime.Unix()-timestamp < containerIDTimeoutSec {
						continue
					}
					delete(d.containerData, containerID)
				}
				count++
			}

		}(now)
	}
}

func (d *DockerInfoManager) GetContainerPid(containerID string) (int, error) {
	if containerID == "" {
		return 0, fmt.Errorf("container ID is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	container, err := d.dockerCli.ContainerInspect(ctx, containerID)
	if err != nil {
		return 0, fmt.Errorf("container inspace failed, %v", err)
	}

	if container.State.Pid <= 0 {
		return 0, fmt.Errorf("get container's pid failed, pid : %v", container.State.Pid)
	}

	return container.State.Pid, nil
}

func (d *DockerInfoManager) getContainerData(pod *corev1.Pod) map[string]*daemon.ContainerData {
	containerData := make(map[string]*daemon.ContainerData, len(pod.Status.ContainerStatuses))

	for _, container := range pod.Status.ContainerStatuses {
		if len(pod.Status.ContainerStatuses) != 1 {
			running := container.State.Running
			if running == nil {
				continue
			}
		}

		cname := container.Name
		id := strings.TrimPrefix(container.ContainerID, "docker://")
		cPid, err := d.GetContainerPid(id)
		if len(cname) == 0 || err != nil {
			logging.Get().Warn().Msgf("get container info failed, namespace : %v, pod name : %v.", pod.GetNamespace(), pod.GetName())
			continue
		}
		//save container information
		containerData[id] = &daemon.ContainerData{
			ContainerName: cname,
			ContainerPid:  cPid,
		}
	}

	if len(containerData) == 0 {
		logging.Get().Warn().Msgf("get container id failed, namespace : %v, pod name : %v.", pod.GetNamespace(), pod.GetName())
	}

	return containerData
}

func (d *DockerInfoManager) dockerEvents() {
	filter := filters.NewArgs(
		filters.Arg("event", "create"),
		filters.Arg("type", "container"),
	)

	msg, errs := d.dockerCli.Events(context.Background(), types.EventsOptions{
		Filters: filter,
	})

	for {
		select {
		case m := <-msg:
			d.saveContainerData(m.ID, m.Time)
		case err := <-errs:
			if err != nil {
				logging.Get().Err(err).Msgf("err returned for docker events. try to restart")
				// try to restart listening to container streams
				msg, errs = d.dockerCli.Events(context.Background(), types.EventsOptions{
					Filters: filter,
				})
			}
		}
	}
}

func (d *DockerInfoManager) Start() error {
	//docker events
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//docker events
		d.dockerEvents()
	}()

	return nil
}

func (d *DockerInfoManager) saveContainerData(containerID string, timestamp int64) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	if len(containerID) == 0 || timestamp <= 0 {
		return
	}

	containerID = strings.TrimPrefix(containerID, "docker://")
	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}
	d.Lock()
	defer d.Unlock()
	d.containerData[containerID] = timestamp
}

func (d *DockerInfoManager) FindContainerCacheData(containerID string) (int64, bool) {
	if len(containerID) == 0 {
		return 0, false
	}
	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}
	d.RLock()
	defer d.RUnlock()
	timestamp, ok := d.containerData[containerID]
	return timestamp, ok
}

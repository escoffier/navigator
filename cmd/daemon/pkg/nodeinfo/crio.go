package nodeinfo

import (
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/logging"
	internalapi "k8s.io/cri-api/pkg/apis"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

var _ ContainerInfoManager = (*CrioInfoManager)(nil)

type CrioInfoManager struct {
	crioCli       internalapi.RuntimeService
	containerData map[string]int64 // map[containerId]time

	sync.RWMutex
}

func NewCrioInfoManager() (*CrioInfoManager, error) {
	uri := os.Getenv("CRIO_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/crio/crio.sock"
	}

	client, err := remote.NewRemoteRuntimeService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("crio new client failed, %v", err)
	}

	rs := &CrioInfoManager{
		crioCli:       client,
		containerData: make(map[string]int64, 30),
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		rs.clearContainerTimeoutData()
	}()

	return rs, nil
}

func (p *CrioInfoManager) clearContainerTimeoutData() {
	return
}

func (p *CrioInfoManager) GetContainerPid(containerID string) (int, string, error) {
	containerID = strings.TrimPrefix(containerID, "cri-o://")
	r, err := p.crioCli.ContainerStatus(containerID, true)
	if err != nil {
		return 0, "", errors.Errorf("get container status by crio failed, %v", err)
	}

	info := r.GetInfo()
	value := info["info"]
	data := make(map[string]interface{})
	err = json.Unmarshal([]byte(value), &data)
	if err != nil {
		return 0, "", errors.Errorf("cri-o json unmarshal failed, %v", err)
	}

	pid := data["pid"]
	if pid == nil {
		return 0, "", errors.Errorf("cri-o container status have not find pid")
	}

	fpid := pid.(float64)

	return int(fpid), containerID, nil
}

func (p *CrioInfoManager) ListenEvents(saveData SaveContainerDataFunc) {
	return
}

func (p *CrioInfoManager) Start() error {
	//docker events
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//docker events
		p.ListenEvents(p.saveContainerData)
	}()

	return nil
}

func (p *CrioInfoManager) saveContainerData(containerID string, timestamp int64) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	if len(containerID) == 0 || timestamp <= 0 {
		return
	}

	containerID = strings.TrimPrefix(containerID, "cri-o://")
	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}

	p.Lock()
	defer p.Unlock()
	p.containerData[containerID] = timestamp
}

func (p *CrioInfoManager) FindContainerCacheData(containerID string) (int64, bool) {
	if len(containerID) == 0 {
		return 0, false
	}

	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}

	p.RLock()
	defer p.RUnlock()
	timestamp, ok := p.containerData[containerID]
	return timestamp, ok
}

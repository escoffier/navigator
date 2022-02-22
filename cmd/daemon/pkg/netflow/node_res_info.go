package netflow

import (
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	containerIDTimeoutSec = int64(60)
)

type NodeResourceInfo struct {
	resInfos      *sync.Map        // map[string]*daemon.K8sResData
	containerData map[string]int64 // map[containerId]time
	sync.RWMutex
}

func NewNodeResourceInfo() *NodeResourceInfo {
	info := &NodeResourceInfo{
		resInfos:      new(sync.Map),
		containerData: make(map[string]int64, 10),
	}
	go info.clearContainerTimeoutData()
	return info
}

func (kri *NodeResourceInfo) SaveK8sResData(ip, ownerName, kind, namespace, podName string, containerInfo map[string]*daemon.ContainerData) {
	if len(ip) == 0 || len(ownerName) == 0 || len(namespace) == 0 || len(containerInfo) == 0 {
		return
	}

	_, ok := kri.resInfos.Load(ip)
	if ok {
		return
	}

	var rsData daemon.K8sResData
	rsData.OwnerName = ownerName
	rsData.Kind = kind
	rsData.PodName = podName
	rsData.Namespace = namespace
	rsData.ContainerInfo = containerInfo
	rsData.ListenPorts = make(map[string]*daemon.ProcessInfo)
	kri.resInfos.LoadOrStore(ip, &rsData)
}

func (kri *NodeResourceInfo) DeleteK8sResData(ip string) {
	if len(ip) == 0 {
		return
	}

	kri.resInfos.Delete(ip)
}

func (kri *NodeResourceInfo) GetK8sResData(ip string) (*daemon.K8sResData, error) {
	if len(ip) == 0 {
		return nil, errors.Errorf("ip address is error")
	}

	v, ok := kri.resInfos.Load(ip)
	if !ok {
		return nil, errors.Errorf("can not find k8s resource data by %s", ip)
	}

	return v.(*daemon.K8sResData), nil
}

func (kri *NodeResourceInfo) UpdateK8sResData(ip, ownerName, kind, namespace, podname string, containerInfo map[string]*daemon.ContainerData) {
	if len(ip) == 0 || len(ownerName) == 0 || len(namespace) == 0 || len(containerInfo) == 0 {
		return
	}

	_, ok := kri.resInfos.Load(ip)
	if ok {
		return
	}

	var rsData daemon.K8sResData
	rsData.OwnerName = ownerName
	rsData.Kind = kind
	rsData.Namespace = namespace
	rsData.PodName = podname
	rsData.ContainerInfo = containerInfo
	rsData.ListenPorts = make(map[string]*daemon.ProcessInfo)
	kri.resInfos.Store(ip, &rsData)
}

func (kri *NodeResourceInfo) SaveContainerData(containerID string, timestamp int64) {
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
	kri.Lock()
	defer kri.Unlock()
	kri.containerData[containerID] = timestamp
}

func (kri *NodeResourceInfo) FindContainerCacheData(containerID string) (int64, bool) {
	if len(containerID) == 0 {
		return 0, false
	}
	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}
	kri.RLock()
	defer kri.RUnlock()
	timestamp, ok := kri.containerData[containerID]
	return timestamp, ok
}

func (kri *NodeResourceInfo) clearContainerTimeoutData() {
	ticker := time.NewTicker(30 * time.Second)
	count := 0
	for now := range ticker.C {
		func(nowTime time.Time) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()

			kri.Lock()
			defer kri.Unlock()

			if count >= 60 { // if a map keeps a stable size but is with continouous add or delete, it should be reconstructed after a period of time to prevent memory leak
				newMap := make(map[string]int64, len(kri.containerData))
				for containerID, timestamp := range kri.containerData {
					if nowTime.Unix()-timestamp >= containerIDTimeoutSec {
						continue
					}
					newMap[containerID] = timestamp
				}
				kri.containerData = newMap
				count = 0
			} else {
				for containerID, timestamp := range kri.containerData {
					if nowTime.Unix()-timestamp < containerIDTimeoutSec {
						continue
					}
					delete(kri.containerData, containerID)
				}
				count++
			}

		}(now)
	}
}

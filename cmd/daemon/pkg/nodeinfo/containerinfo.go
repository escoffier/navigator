package nodeinfo

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
)

var ExportRawContainer = true

type ContainerInfoManager interface {
	clearContainerTimeoutData()
	GetContainerPid(containerID string) (int, string, error)
	ListenEvents(saveData SaveContainerDataFunc)
	saveContainerData(containerID string, timestamp int64)
	FindContainerCacheData(containerID string) (int64, bool)
	Start() error
	AddEventHandler(handler ContainerEventHandler)
	SetPodStore(store containerassets.PodCache)
	// RunCmd 响应如果无stderr信息，resp则为stdout的内容；否则 resp格式为： stdout:xxx\nstderr:xxx
	RunCmd(ctx context.Context, containerId string, cmd []string) (resp string, err error)
}

type SaveContainerDataFunc func(containerID string, timestamp int64)

type ContainerEventHandler interface {
	OnAdd(obj interface{})
	OnUpdate(oldObj, newObj interface{})
	OnDelete(obj interface{})
}

type ContainerEventHandlerFuncs struct {
	AddFunc    func(obj interface{})
	UpdateFunc func(oldObj, newObj interface{})
	DeleteFunc func(obj interface{})
}

func (c ContainerEventHandlerFuncs) OnAdd(obj interface{}) {
	if c.AddFunc != nil {
		c.AddFunc(obj)
	}
}

func (c ContainerEventHandlerFuncs) OnUpdate(oldObj, newObj interface{}) {
	if c.UpdateFunc != nil {
		c.UpdateFunc(oldObj, newObj)
	}
}

func (c ContainerEventHandlerFuncs) OnDelete(obj interface{}) {
	if c.DeleteFunc != nil {
		c.DeleteFunc(obj)
	}
}

package nodeinfo

type ContainerInfoManager interface {
	clearContainerTimeoutData()
	GetContainerPid(containerID string) (int, string, error)
	ListenEvents(saveData SaveContainerDataFunc)
	saveContainerData(containerID string, timestamp int64)
	FindContainerCacheData(containerID string) (int64, bool)
	Start() error
}

type SaveContainerDataFunc func(containerID string, timestamp int64)

package kuberneteshelper

import (
	"errors"
	"sync"
	"time"

	ps "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/go-ps"
)

func NewContainerCache() ContainerCache {
	return ContainerCache{
		lock:            &sync.RWMutex{},
		containerCache:  make(map[int]string),
		kubernetesCache: make(map[int]string),
	}
}

type ContainerCache struct {
	lock            *sync.RWMutex
	containerCache  map[int]string
	kubernetesCache map[int]string
}

//cleanupLoop that keeps calling cleanupCache() in a loop every scheduled interval
func (cc ContainerCache) cleanupLoop() {
	//Hardcoded to run once a minute. TODO: make this configurable
	for range time.Tick(time.Minute * 1) {
		cc.cleanupCache()
	}

}

// This function is meant to clean up the pids that have entries in the cache by the
// corresponding processes have exited
func (cc ContainerCache) cleanupCache() {
	for pid := range cc.containerCache {
		p, err := ps.FindProcess(pid)
		if err != nil || p == nil {
			cc.Delete(pid)
		}
	}
}

// Set stores the PID and the container Id in the map. If the container id is not available, it will be stored as "non-container".
// If the process tree is killed by the time the container ID is fetched, it will be marked as "killed" as a hint to be purged.
func (cc ContainerCache) Set(dockerPid int, cid string, kid string) error {
	cc.lock.Lock()
	defer cc.lock.Unlock()
	cc.containerCache[dockerPid] = cid
	cc.kubernetesCache[dockerPid] = kid
	return nil
}

// Get retrieves the cid, given the pid.
func (cc ContainerCache) Get(dockerPid int) (string, string, error) {
	cc.lock.RLock()
	cid, ok := cc.containerCache[dockerPid]
	kid, ok := cc.kubernetesCache[dockerPid]
	cc.lock.RUnlock()

	if ok {
		return cid, kid, nil
	} else {
		return "", "", errors.New("CID not found in cache")
	}
}

func (cc ContainerCache) Delete(dockerPid int) error {
	cc.lock.Lock()
	defer cc.lock.Unlock()
	delete(cc.containerCache, dockerPid)
	delete(cc.kubernetesCache, dockerPid)
	return nil
}

func (cc ContainerCache) Init() error {
	//Launch a seperate cleanup job thread
	go cc.cleanupLoop()
	return nil
}

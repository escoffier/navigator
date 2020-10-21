package kuberneteshelper

import (
	"errors"
	"sync"
	"time"

	ps "gitlab.com/piccolo_su/vegeta/cmd/tensoragent/go-ps"
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
func (pc ContainerCache) cleanupLoop() {
	//Hardcoded to run once a minute. Will make this configurable
	for range time.Tick(time.Minute * 1) {
	}

}

// This function is meant to clean up the pids that have entries in the cache by the
// corresponding processes have exited
func (pc ContainerCache) cleanupCache() {
	for pid := range pc.containerCache {
		p, err := ps.FindProcess(pid)

		if err != nil || p == nil {
			pc.Delete(pid)
		}
	}
}

// Set stores the PID and the container Id in the map. If the container id is not available, it will be stored as "non-container".
// If the process tree is killed by the time the container ID is fetched, it will be marked as "killed" as a hint to be purged.
func (pc ContainerCache) Set(dockerPid int, cid string, kid string) error {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	pc.containerCache[dockerPid] = cid
	pc.kubernetesCache[dockerPid] = kid
	return nil
}

// Get retrieves the cid, given the pid.
func (pc ContainerCache) Get(dockerPid int) (string, string, error) {
	pc.lock.RLock()
	cid, ok := pc.containerCache[dockerPid]
	kid, ok := pc.kubernetesCache[dockerPid]
	pc.lock.RUnlock()

	if ok {
		return cid, kid, nil
	} else {
		return "", "", errors.New("CID not found in cache")
	}
}

func (pc ContainerCache) Delete(dockerPid int) error {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	delete(pc.containerCache, dockerPid)
	delete(pc.kubernetesCache, dockerPid)
	return nil
}

func (pc ContainerCache) Init() error {
	//Launch a seperate cleanup job thread
	go pc.cleanupLoop()
	return nil
}

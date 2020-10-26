package containerhelper

import (
	"errors"
	"sync"
	"time"

	ps "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/go-ps"
)

// NewPidCache instantiates a default password store
func NewPidCache() PidCache {
	return PidCache{
		lock:     &sync.RWMutex{},
		pidCache: make(map[int]int),
	}
}

// PidCahe is for pid-dockerpid cache.
type PidCache struct {
	lock     *sync.RWMutex
	pidCache map[int]int
}

//cleanupLoop that keeps calling cleanupCache() in a loop every scheduled interval
func (pc PidCache) cleanupLoop() {
	//Hardcoded to run once a minute. TODO: make this configurable
	for range time.Tick(time.Minute * 1) {
		pc.cleanupCache()
	}

}

// This function is meant to clean up the pids that have entries in the cache by the
// corresponding processes have exited
func (pc PidCache) cleanupCache() {
	for pid := range pc.pidCache {
		p, err := ps.FindProcess(pid)

		if err != nil || p == nil {
			pc.Delete(pid)
		}
	}
}

// Set stores the PID and the container Id in the map. If the container id is not available, it will be stored as "non-container".
// If the process tree is killed by the time the container ID is fetched, it will be marked as "killed" as a hint to be purged.
func (pc PidCache) Set(pid int, cid int) error {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	pc.pidCache[pid] = cid
	return nil
}

// Get retrieves the cid, given the pid.
func (pc PidCache) Get(pid int) (int, error) {
	pc.lock.RLock()
	cid, ok := pc.pidCache[pid]
	pc.lock.RUnlock()

	if ok {
		return cid, nil
	}
	return 0, errors.New("PID not found in cache")
}

// Delete removes cache pid.
func (pc PidCache) Delete(pid int) error {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	delete(pc.pidCache, pid)
	return nil
}

// Init initializes the cache.
func (pc PidCache) Init() error {
	//Launch a seperate cleanup job thread
	go pc.cleanupLoop()
	return nil
}

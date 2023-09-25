package scanjob

import (
	"sync"
)

type TaskQueue struct {
	WG    sync.Locker
	Tasks map[int64]string
}

func NewTaskQueue() *TaskQueue {
	s := &TaskQueue{
		WG:    &sync.Mutex{},
		Tasks: make(map[int64]string),
	}
	return s
}

func (vi *TaskQueue) Set(regID int64) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	vi.Tasks[regID] = ""
}

func (vi *TaskQueue) Get(regID int64) bool {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	_, ok := vi.Tasks[regID]
	return ok
}

func (vi *TaskQueue) Delete(regID int64) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	delete(vi.Tasks, regID)
}

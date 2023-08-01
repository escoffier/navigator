package sync

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

func (vi *TaskQueue) Set(regID int64, status string) {
	vi.WG.Lock()
	defer vi.WG.Unlock()

	vi.Tasks[regID] = status
}

func (vi *TaskQueue) Get(regID int64) (string, bool) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	sta, ok := vi.Tasks[regID]
	return sta, ok
}

func (vi *TaskQueue) Delete(regID int64) {
	vi.WG.Lock()
	defer vi.WG.Unlock()
	delete(vi.Tasks, regID)
}

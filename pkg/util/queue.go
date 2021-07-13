package util

import (
	"container/list"
	"sync"
)

// simple Concurrency Safe Queue
type Queue struct {
	data *list.List
	sync.RWMutex
}

func NewQueue() *Queue {
	return &Queue{
		data: list.New(),
	}
}

func (b *Queue) Len() int {
	b.RLock()
	defer b.RUnlock()

	return b.data.Len()
}

func (b *Queue) Add(item interface{}) {
	if item == nil {
		return
	}
	b.Lock()
	defer b.Unlock()

	b.data.PushBack(item)
}

func (b *Queue) Pop() (item interface{}, exist bool) {
	b.Lock()
	defer b.Unlock()

	elem := b.data.Front()
	if elem == nil {
		return nil, false
	}

	b.data.Remove(elem)
	return elem.Value, true
}

func (b *Queue) Peek() (item interface{}, exist bool) {
	b.RLock()
	defer b.RUnlock()

	elem := b.data.Front()
	if elem == nil {
		return nil, false
	}
	return elem.Value, true
}

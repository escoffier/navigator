package util

import (
	"container/list"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

// simple Concurrency Safe Queue
type Queue struct {
	data       *list.List
	notifyChan chan struct{}
	sync.RWMutex
}

func NewQueue() *Queue {
	return &Queue{
		data:       list.New(),
		notifyChan: make(chan struct{}, 1),
	}
}

func (b *Queue) Len() int {
	b.RLock()
	defer b.RUnlock()

	return b.data.Len()
}

func (b *Queue) sendNotif() {
	select {
	case b.notifyChan <- struct{}{}:
	default:
		return
	}
}
func (b *Queue) Add(item interface{}) {
	if item == nil {
		return
	}
	b.Lock()
	defer b.Unlock()

	b.data.PushBack(item)
	b.sendNotif()
}

type ConsumeFunc func(item interface{})

func (b *Queue) consumeItem(item interface{}, consumeFunc ConsumeFunc) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()
	consumeFunc(item)
}
func (b *Queue) Consume(consumeFunc ConsumeFunc) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(1000 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-b.notifyChan:
				for b.Len() > 0 {
					item, exist := b.Pop()
					if exist && item != nil {
						b.consumeItem(item, consumeFunc)
					}

				}
			case <-ticker.C:
				for b.Len() > 0 {
					item, exist := b.Pop()
					if !exist && item != nil {
						b.consumeItem(item, consumeFunc)
					}
				}
			}
		}
	}()
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

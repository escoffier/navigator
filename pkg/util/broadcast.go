package util

import (
	"context"
	"fmt"
	"gitlab.com/security-rd/go-pkg/logging"
	"sync"
	"time"
)

type BroadcastServer struct {
	sync.RWMutex
	source    chan interface{}
	listeners map[string]chan interface{}
}

func (b *BroadcastServer) AddMsg(msg interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	select {
	case b.source <- msg:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("add msg timeout.%v", ctx.Err())
	}
}

func (b *BroadcastServer) Subscribe(name string) <-chan interface{} {
	b.Lock()
	defer b.Unlock()
	v, ok := b.listeners[name]
	if ok {
		return v
	}
	b.listeners[name] = make(chan interface{})

	return b.listeners[name]
}

func (b *BroadcastServer) CancelSubscription(name string) error {
	b.Lock()
	defer b.Unlock()
	delete(b.listeners, name)
	return nil
}

func (b *BroadcastServer) Serve(ctx context.Context) {
	defer func() {
		b.Lock()
		defer b.Unlock()
		for _, listener := range b.listeners {
			if listener != nil {
				close(listener)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logging.Get().Error().Msg("server exit")
			return
		case val, ok := <-b.source:
			if !ok {
				logging.Get().Error().Msg("failed to read msg from source channel")
				return
			}
			b.Lock()
			for name, listener := range b.listeners {
				if listener == nil {
					logging.Get().Warn().Str("name", name).Msg("listener is nil")
					continue
				}
				func() {
					tmpCtx, tmpCancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer tmpCancel()
					select {
					case listener <- val:
						logging.Get().Debug().Str("name", name).Msg("publish msg to subscriber ok")
					case <-tmpCtx.Done():
						logging.Get().Error().Str("name", name).Msg("failed to publish msg to subscriber")
					}
				}()
			}
			b.Unlock()
		}
	}
}

func NewBroadcastServer() *BroadcastServer {
	service := &BroadcastServer{
		source:    make(chan interface{}, 10),
		listeners: make(map[string]chan interface{}),
	}
	return service
}

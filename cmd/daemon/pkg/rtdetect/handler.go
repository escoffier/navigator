package rtdetect

import (
	"context"
	"errors"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	defaultBufSize = 100
)

var (
	ErrBufferFull = errors.New("buffer full")
)

type RuntimeRulesManager interface {
	GetRule(ruleName string) (*model.RuleFromYaml, bool)
}
type eventItem struct {
	data       *outputs.Response
	uuid       uint64
	clusterKey string
}
type eventsHandler interface {
	Handle(ctx context.Context, events []eventItem) error
	CheckTarget(ctx context.Context, event eventItem) bool
}

type SyncHandler struct {
	ehandler eventsHandler
}

func NewSyncHandler(handler eventsHandler) *SyncHandler {
	return &SyncHandler{handler}
}

func (h *SyncHandler) Put(ctx context.Context, event eventItem) error {
	return h.ehandler.Handle(ctx, []eventItem{event})
}

func (h *SyncHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	return h.ehandler.CheckTarget(ctx, event)
}

type AsyncHandler struct {
	input      chan eventItem
	ehandler   eventsHandler
	interval   time.Duration
	bufferSize int
	missCnt    int32
}

func NewAsyncHandler(handler eventsHandler, interval time.Duration, bufferSize int) *AsyncHandler {
	if bufferSize == 0 {
		bufferSize = defaultBufSize
	}
	h := AsyncHandler{
		input:      make(chan eventItem, bufferSize),
		ehandler:   handler,
		interval:   interval,
		bufferSize: bufferSize,
		missCnt:    0,
	}
	h.asyncLoop()

	return &h
}

func (h *AsyncHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	return h.ehandler.CheckTarget(ctx, event)
}

func (h *AsyncHandler) Put(ctx context.Context, event eventItem) error {
	select {
	case h.input <- event:
		return nil
	default:
		logging.GetLogger().Warn().Msgf("buffer full. lost event: %+v", event)
		atomic.AddInt32(&h.missCnt, 1)
		return ErrBufferFull
	}

}

func (h *AsyncHandler) submit(ctx context.Context, buff []eventItem) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := h.ehandler.Handle(ctx, buff); err != nil {
		logging.GetLogger().Err(err).Msgf("buffer submit error. data: %v", buff)
	}
}

func (h *AsyncHandler) consumePeriodically(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()

	buffer := make([]eventItem, 0, h.bufferSize)
	toStop := false
	for i := 0; i < h.bufferSize && !toStop; i++ {
		select {
		case e := <-h.input:
			buffer = append(buffer, e)
		default:
			toStop = true
			break
		}
	}

	go h.submit(context.Background(), buffer)
}

func (h *AsyncHandler) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		if h.interval == 0 {
			for {
				select {
				case evt := <-h.input:
					go h.submit(context.Background(), []eventItem{evt})
				}
			}

		} else {
			ticker := time.NewTicker(h.interval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					h.consumePeriodically(context.Background())
					atomic.StoreInt32(&h.missCnt, 0)
				}
			}
		}

	}()
}

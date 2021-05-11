package mongotools

import (
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"go.mongodb.org/mongo-driver/event"
)

var (
	poolCnt int64 = 0
)

func init() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("panic: %v", r)
			}
		}()

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				size := atomic.LoadInt64(&poolCnt)
				logging.GetLogger().Debug().Msgf("Mongo Connection Pool size: %d", size)
			}
		}

	}()
}
func PoolMonitorFunc(event *event.PoolEvent) {
	if event.Type == "ConnectionCheckedIn" {
		atomic.AddInt64(&poolCnt, 1)
	} else if event.Type == "ConnectionCheckedOut" {
		atomic.AddInt64(&poolCnt, -1)
	}
}

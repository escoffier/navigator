// Package mozart
// hangup 的功能是将一个任务暂时挂起，等到任务上的再次执行时间再重新执行
// 具体场景是mozart的某些步骤会判断x秒内是否发生过什么事，一直阻塞等待x秒并不合理，这里采取先挂起，x秒后重新来检查的方式

package mozart

import (
	"gitlab.com/security-rd/go-pkg/logging"
	"time"
)

var sessionHangupQueue chan work

type work struct {
	Event         Event
	Rules         RulesNew
	JsonEvent     map[string]interface{}
	SessionStatus map[string]interface{}
	NextTime      time.Time
}

func initHangupQueue(e *Engine) {
	sessionHangupQueue = make(chan work, 1000)
	var w work
	var tempW *work

	go func() {
		var err error
		ticker := time.NewTicker(time.Millisecond * 500)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				breakT := false
				now := time.Now()
				for {
					if tempW != nil {
						w = *tempW
						tempW = nil
					} else {
						w = <-sessionHangupQueue
					}
					if w.NextTime.Before(now) {
						err = e.pool.Invoke(jobArgs{
							Event:         w.Event,
							Rules:         w.Rules,
							JsonEvent:     w.JsonEvent,
							SessionStatus: w.SessionStatus,
						})
						if err != nil {
							logging.Get().Error().Err(err).Interface("event", w.Event).Interface("session status", w.SessionStatus).Msg("send work to pool fails")
						}
					} else {
						tempW = &w
						breakT = true
						break
					}
				}
				if breakT {
					break
				}
			}
		}
	}()
}

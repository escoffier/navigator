package hunter

import (
	"context"
	"runtime/debug"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (s *Service) expireRecordLoop() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when expire kube-scanner record: %v. stack: %s", r, debug.Stack())
		}
	}()

	// wait for server to be ready
	time.Sleep(time.Second * 5)

	s.expireRecord(time.Now())
	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()
	for {
		t := <-ticker.C
		s.expireRecord(t)
	}
}

const (
	expireTaskTimeout = time.Second * 5
)

func (s *Service) expireRecord(t time.Time) {
	logging.GetLogger().Info().Msgf("expire kube-scanner record run")
	ctx, cancel := context.WithTimeout(context.Background(), expireTaskTimeout)
	defer cancel()
	retryFunc := func() error {
		return s.taskManager.DealExpireRecords(ctx, t)
	}
	if err := util.WithRetry(retryFunc, util.DefaultRetryConf); err != nil {
		logging.GetLogger().Error().Msgf("DealExpireRecords fail, err:%s", err.Error())
	}
}

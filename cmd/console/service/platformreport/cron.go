package platformreport

import (
	"context"
	"runtime/debug"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (s *Service) expireTaskLoop() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when expire report task: %v. stack: %s", r, debug.Stack())
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
	logging.GetLogger().Info().Msgf("expire report task run")
	ctx, cancel := context.WithTimeout(context.Background(), expireTaskTimeout)
	defer cancel()
	retryFunc := func() error {
		return s.manager.DealExpireRecords(ctx, t)
	}
	if err := util.WithRetry(retryFunc, util.DefaultRetryConf); err != nil {
		logging.GetLogger().Error().Msgf("DealExpireRecords fail, err:%s", err.Error())
	}
}

const (
	scheduleInterval = time.Hour
)

func (s *Service) schedule() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when schedule tasks: %v. stack: %s", r, debug.Stack())
		}
	}()
	ticker := time.NewTicker(scheduleInterval)
	defer ticker.Stop()
	for t := range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		templates, err := s.manager.LoadAllTaskTemplates(ctx)
		cancel()
		if err != nil {
			logging.GetLogger().Err(err).Msg("LoadAllCronReportTasks")
			continue
		}

		for _, template := range templates {
			if err = s.handleTaskAsync(template, t); err != nil {
				logging.GetLogger().Err(err).Msgf("handle task fail, taskID:%d", template.ID)
			}
		}
	}
}

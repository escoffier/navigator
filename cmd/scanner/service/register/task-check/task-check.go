// Package task_check check subtask executing time,set it failed where timeout
// eg: when db exception,or service restart, processing subtask will not change its status and update its heartbeat
// task-check will set these subtasks to timeout, and also set task to exception.
// engine will retry these task

package taskcheck

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName                        = "task-check"
	checkInterval                      = 30
	defaultTimeOutMin                  = 60
	HeartBeatTimeOutMsg                = "heart beat time out"
	TaskStatusInConsistentWithSubtasks = "task in processing status while all subtasks are finished"
)

type TaskCheck struct {
	taskSrv *task.TaskSrv
}

func (t *TaskCheck) checkTaskStatus() error {
	// only check progressing task
	pt, err := t.taskSrv.GetProgressingTasks()
	if err != nil {
		logging.GetLogger().Err(err).Msg("get progressing task err")
		return err
	}
	for _, v := range pt {
		sts, err := t.taskSrv.GetProgressingSubTasks([]int64{v.ID})
		if err != nil {
			logging.GetLogger().Err(err).Int64("taskId", v.ID).Msg("get progressing subtask err")
			continue
		}
		if len(sts) == 0 {
			continue
		}

		if v.ScannerID != global.ScannerPodID {
			// a processing task's scanner id not consistent with mine
			// which means original scanner give up control of the task (eg: scanner reboot)
			// so we take over,reset task status to pending

			if err := t.taskSrv.AddSubTaskRetryCount(sts); err != nil {
				logging.GetLogger().Err(err).
					Int64("taskId", v.ID).
					Msg("reschedule AddSubTaskRetryCount err")
				return err
			}

			if err := t.taskSrv.ReScheduleSubTask(sts); err != nil {
				logging.GetLogger().Err(err).
					Int64("taskId", v.ID).
					Msg("reschedule subtask err")
			} else {
				logging.GetLogger().Info().
					Int64("taskId", v.ID).
					Msg("reschedule subtask ok")
			}

			if err := t.taskSrv.ReScheduleTask([]int64{v.ID}); err != nil {
				logging.GetLogger().Err(err).
					Int64("taskId", v.ID).
					Msg("reschedule task err")
			} else {
				logging.GetLogger().Info().
					Int64("taskId", v.ID).
					Msg("reschedule task ok")
			}
		}
	}
	return nil
}

func (t *TaskCheck) Start(ctx context.Context) error {
	logging.GetLogger().Debug().Msg("task-check started")

	for {
		time.Sleep(time.Duration(checkInterval) * time.Second)

		// check task status
		_ = t.checkTaskStatus()

	}
}

func (t *TaskCheck) Stop(ctx context.Context) error {

	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	t := &TaskCheck{}
	taskSrv := task.NewTaskSrv()
	t.taskSrv = taskSrv

	return t, nil
}

// Package task_check check subtask executing time,set it failed where timeout
// eg: when db exception,or service restart, processing subtask will not change its status and update its heartbeat
// task-check will set these subtasks to timeout, and also set task to exception.
// engine will retry these task

package task_check

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

func (t *TaskCheck) checkSubTaskTimeout() error {
	// check subtask timeout
	sts, err := t.taskSrv.GetProgressingSubTasks(nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get processing sub tasks failed,ignore checking heart beat")
		return err
	}
	for _, st := range sts {
		tc := time.Since(*st.HeartBeat).Minutes()
		if tc > defaultTimeOutMin {
			err := t.taskSrv.SetSubTaskFailed(st.Id, HeartBeatTimeOutMsg)
			if err != nil {
				logging.GetLogger().Err(err).
					Int64("taskId", st.TaskId).
					Int64("subtaskId", st.Id).
					Msg("subtask timeout,but update db failed")
			} else {
				logging.GetLogger().Info().
					Int64("taskId", st.TaskId).
					Int64("subtaskId", st.Id).
					Msg("subtask timeout")
			}
		}
	}
	return nil
}

func (t *TaskCheck) checkTaskStatus() error {
	// only check progressing task
	pt, err := t.taskSrv.GetProgressingTasks()
	if err != nil {
		logging.GetLogger().Err(err).Msg("get progressing task err")
		return err
	}
	for _, v := range pt {
		sts, err := t.taskSrv.GetProgressingSubTasks([]int64{v.Id})
		if err != nil {
			logging.GetLogger().Err(err).Int64("taskId", v.Id).Msg("get progressing subtask err")
			continue
		}

		pendingSubtasks, err := t.taskSrv.GetPendingSubTasks([]int64{v.Id})
		if err != nil {
			logging.GetLogger().Err(err).Int64("taskId", v.Id).Msg("get pending subtask err")
			continue
		}

		if len(sts) == 0 && len(pendingSubtasks) == 0 {
			// not processing subtask,so we set task end and set result failed
			if err := t.taskSrv.SetTaskFailed(v.Id, TaskStatusInConsistentWithSubtasks); err != nil {
				logging.GetLogger().Err(err).
					Int64("taskId", v.Id).
					Msg("task is processing status while all subtasks are finished. but update task db status failed.")
			} else {
				logging.GetLogger().Info().
					Int64("taskId", v.Id).
					Msg("task is processing status while all subtasks are finished.")
			}
		}

		if len(pendingSubtasks) != 0 && v.ScannerId != global.ScannerId {
			// a processing task with pending subtasks,but scanner id not mine
			// which means original scanner give up control of the task (eg: scanner reboot)
			// so we take over,reset task status to pending
			if err := t.taskSrv.ReScheduleTask([]int64{v.Id}); err != nil {
				logging.GetLogger().Err(err).
					Int64("taskId", v.Id).
					Msg("reschedule task err")
			} else {
				logging.GetLogger().Info().
					Int64("taskId", v.Id).
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

		// check subtask timeout
		_ = t.checkSubTaskTimeout()

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
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	t := &TaskCheck{}
	taskSrv := task.NewTaskSrv()
	t.taskSrv = taskSrv

	return t, nil
}

package task

import (
	"context"
	"fmt"
	"sync"
	"time"

	flow_conf "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/flow-conf"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"golang.org/x/sync/semaphore"
)

type WalkTaskFunc func(t *Task, limit *semaphore.Weighted, flow flow_conf.FlowConf) error
type WalkSubTaskFunc func(t *Task, st *SubTask, subLimit *semaphore.Weighted, flow flow_conf.FlowConf, wg *sync.WaitGroup) error

func GetFlowNameByTask(t *Task) string {
	return t.FlowConf
}

func WalkTasks(ctx context.Context, tasks []Task, limit *semaphore.Weighted, taskFn WalkTaskFunc) error {
	taskSrv := NewTaskSrv()
	for k, t := range tasks {
		// Stop processing task during DB update
		global.TiDbUpdateWg.Wait()

		logging.GetLogger().Info().Int64("taskId", t.Id).Msg("start task")

		if err := limit.Acquire(ctx, 1); err != nil {
			logging.GetLogger().Err(err).Int64("taskId", t.Id).Msg("acquire semaphore err")
			if err2 := taskSrv.SetTaskFailed(t.Id, fmt.Sprintf("wait schedule timeout:%v", err)); err2 != nil {
				logging.GetLogger().Err(err).Int64("taskId", t.Id).Msg("set task status err")
			}
			continue
		}

		// get flow conf by task info
		flowConf, err := flow_conf.GetFlowConf(GetFlowNameByTask(&t))
		if err != nil {
			logging.GetLogger().Err(err).Msg("get flow err")
			if err2 := taskSrv.SetTaskFailed(t.Id, fmt.Sprintf("not find task's flow config:%v", err)); err2 != nil {
				logging.GetLogger().Err(err).Int64("taskId", t.Id).Msg("set task status err")
			}
			continue
		}

		// Wait for all tasks to be processed before DB update
		global.TaskWg.Add(1)

		err = taskFn(&tasks[k], limit, flowConf)
		if err != nil {
			logging.GetLogger().Err(err).Int64("taskId", t.Id).Msg("walker task function err")
		}
	}
	return nil
}

func WalkSubTasks(ctx context.Context,
	t *Task,
	subtasks []SubTask,
	subLimit *semaphore.Weighted,
	flow flow_conf.FlowConf,
	wg *sync.WaitGroup,
	subtaskFn WalkSubTaskFunc) error {

	taskSrv := NewTaskSrv()
	if err := taskSrv.UpdateTaskStartTime(t.Id, time.Now()); err != nil {
		logging.GetLogger().Err(err).Int64("taskId", t.Id).Msg("update task start time err")
		return err
	}

	for k, subTask := range subtasks {
		// if !isSubtaskWaitSchedule(subTask.Status) {
		//	// we will rescan failed task which may contain some success subtask in last scan, so we filter these subtasks
		//	logging.GetLogger().Info().
		//		Int64("subTaskId", subTask.Id).
		//		Int64("taskId", t.Id).
		//		Uint8("status", subTask.Status).
		//		Msg("skip scanned subtask ")
		//	continue
		// }

		logging.GetLogger().Debug().Int64("subTaskId", subTask.Id).Int64("taskId", t.Id).Msg("subtask wait semaphore")
		if err := subLimit.Acquire(ctx, 1); err != nil {
			logging.GetLogger().Error().Err(err).Msg("semaphore acquire err")
			continue
		}

		// after acquire semaphore, check task if suspended
		suspended, err := taskSrv.IsTaskSuspended(t.Id)
		if err == nil && suspended {
			logging.GetLogger().Info().Int64("taskId", t.Id).Msg("task is suspended, ignoring left over subtask")
			subLimit.Release(1)
			break
		}

		logging.GetLogger().Debug().Int64("subTaskId", subTask.Id).Int64("taskId", t.Id).Msg("start subtask")

		wg.Add(1)
		if err := subtaskFn(t, &subtasks[k], subLimit, flow, wg); err != nil {
			logging.GetLogger().Err(err).Int64("subTaskId", subTask.Id).Int64("taskId", t.Id).Msg("subtask function err")
		}
	}
	wg.Wait()
	logging.GetLogger().Info().Int64("taskId", t.Id).Msg("task end")

	// only set task status,not set scan result which decided by all subtask's scan result
	// SetTaskEnd: will ignore suspended task
	_ = taskSrv.SetTaskEnd(t.Id)

	return nil
}

// func isSubtaskWaitSchedule(status uint8) bool {
//	return status == consts.ImageScanPending || status == consts.ImageNotScan
// }

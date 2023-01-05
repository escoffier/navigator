package dequeue

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	dbDequeueName   = "db-dequeue"
	DefaultDbDeqNum = 1
)

type DbConfig struct {
	DequeNum int
}

type DbDequeue struct {
	config DbConfig
}

func (d *DbDequeue) DequeueTasks(ctx context.Context) ([]task.Task, error) {
	// get pending tasks
	maxTask, err := strconv.Atoi(os.Getenv("MAX_INPROGRESS_TASK_NUM"))
	if err != nil || maxTask <= 0 {
		maxTask = consts.DefaultMaxInProgressTask
	}
	registryDal := store.NewRegistryDao(store.GetScannerWrapperDb())

	regs, _, err := registryDal.SearchRegistry(ctx, store.SearchRegistryParam{ScannerInstance: global.ScannerInstance}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Str("scannerInstance", global.ScannerInstance).Msg("GetPendingTasks.SearchRegistry")
		return nil, err
	}
	regIds := make([]int64, 0)
	for i := range regs {
		regIds = append(regIds, regs[i].ID)
	}
	if len(regIds) == 0 {
		logging.GetLogger().Warn().Str("scannerInstance", global.ScannerInstance).Msg("scanner not bind any registry")
		return nil, nil
	}

	taskDal := store.GetScannerOrmDb()
	tasks, err := taskDal.GetInprogressTaskAndSetStatus(ctx, int64(maxTask), int64(d.config.DequeNum), regIds)
	logging.GetLogger().Info().Interface("tasks", tasks).Msg("DequeueTasks GetInProgressTaskAndSetStatus")
	if err != nil {
		logging.GetLogger().Err(err).Msg("DequeueTasks GetInProgressTaskAndSetStatus")
		return nil, err
	}
	pendingTasks := make([]task.Task, 0)
	if len(tasks) == 0 {
		return pendingTasks, nil
	}
	ts := task.NewTaskSrv()
	for _, v := range tasks {
		// get subtasks by task id
		subtasks, err := ts.GetPendingSubTasksByTaskID(ctx, v.ID)
		if err != nil {
			// set task failed
			_ = ts.SetTaskFailed(v.ID, fmt.Sprintf("get subtask err:%v", err))
			continue
		}
		if len(subtasks) == 0 {
			_ = ts.SetTaskFailed(v.ID, "not found valid subtasks")
			continue
		}

		// generate scan policy by db policy id
		st, err := ts.GenerateScanTypeByPolicy(ctx, v.PolicyId)
		if err != nil {
			// set task failed
			_ = ts.SetTaskFailed(v.ID, fmt.Sprintf("get policy err:%v", err))
			continue
		}

		tmpTask := task.Task{
			ID:       v.ID,
			FlowConf: v.FlowConf,
			Scope: task.ScanScope{
				Type:     v.ScopeType,
				SubTasks: subtasks,
			},
			ScanType: st,
			Status:   v.Status,
			Result:   v.Result,
		}
		pendingTasks = append(pendingTasks, tmpTask)
	}
	return pendingTasks, nil
}

func init() {
	err := Register(dbDequeueName, newDbDequeue)
	if err != nil {
		logging.GetLogger().Err(err).Str("Name", dbDequeueName).Msg("init dequeue err")
	}
}

func newDbDequeue(config Config) (Dequeue, error) {
	d := &DbDequeue{}
	d.config.DequeNum = DefaultDbDeqNum

	// parse config
	// bytes, err := yaml.Marshal(config.Options)
	// if err != nil {
	//	return nil, fmt.Errorf("db dequeuer: could not load configuration: %v", err)
	// }
	// err = yaml.Unmarshal(bytes, &d.config)
	// if err != nil {
	//	return nil, fmt.Errorf("db dequeuer: could not load configuration: %v", err)
	// }

	return d, nil
}

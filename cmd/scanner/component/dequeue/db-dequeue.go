package dequeue

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
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
	ts := task.NewTaskSrv()
	tasks, err := ts.GetPendingTasks(ctx, int64(d.config.DequeNum))
	if err != nil {
		logging.GetLogger().Err(err).Msg("get pending tasks err")
		return nil, err
	}

	// update task status
	ids := make([]int64, 0)
	for _, v := range tasks {
		ids = append(ids, v.Id)
	}
	err = ts.SetTasksInProgress(ids)
	if err != nil {
		logging.GetLogger().Err(err).Msg("set task status to in progress err")
		return nil, err
	}
	logging.GetLogger().Trace().Interface("tasks", tasks).Msg("dequeue task")

	return tasks, nil
}

func init() {
	err := Register(dbDequeueName, newDbDequeue)
	if err != nil {
		logging.GetLogger().Err(err).Str("Name", dbDequeueName).Msg("init dequeue err")
	}
}

func newDbDequeue(config DequeueConfig) (Dequeue, error) {
	d := &DbDequeue{}
	d.config.DequeNum = DefaultDbDeqNum

	// parse config
	//bytes, err := yaml.Marshal(config.Options)
	//if err != nil {
	//	return nil, fmt.Errorf("db dequeuer: could not load configuration: %v", err)
	//}
	//err = yaml.Unmarshal(bytes, &d.config)
	//if err != nil {
	//	return nil, fmt.Errorf("db dequeuer: could not load configuration: %v", err)
	//}

	return d, nil
}

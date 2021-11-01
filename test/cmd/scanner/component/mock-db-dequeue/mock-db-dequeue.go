package mock_db_dequeue

import (
	"context"
	"encoding/json"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dequeue"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/test/cmd/scanner/store"
	"gorm.io/gorm"
)

const (
	MockDbDequeueName = "mock-db-dequeue"
)

type MockDbDeqConfig struct {
	DequeNum int
}

type MockDbDequeue struct {
	Db     *store.MockScannerOrm
	GormDb *gorm.DB
	config MockDbDeqConfig
}

func transSubTask(st *model.SubTask) *task.SubTask {
	s := task.SubTask{}
	s.TaskId = st.TaskId
	s.Image.Id = st.ImageId
	//s.Image.RepoName = st.RepoName
	//s.Image.Tag = st.Tag
	return &s
}

func transTask(t *model.Task) (*task.Task, error) {
	sc := make([]task.ScanConfig, 0)
	err := json.Unmarshal([]byte(t.ScanType), &sc)
	if err != nil {
		return nil, err
	}
	scanType := make(map[task.ScanType]task.ScanPolicy)
	for _, v := range sc {
		scanType[task.ScanType(v.Type)] = task.ScanPolicy(v.Policy)
	}

	tmpTask := &task.Task{}
	tmpTask.Id = t.ID
	tmpTask.FlowConf = t.FlowConf
	tmpTask.ScanType = scanType
	tmpTask.Scope.Type = t.ScopeType
	return tmpTask, nil
}

func (d *MockDbDequeue) DequeueTasks(ctx context.Context) ([]task.Task, error) {
	//
	tasks, err := d.Db.GetTask(ctx, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get tasks failed")
		return nil, err
	}
	subtasks, err := d.Db.GetSubTask(ctx, nil)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get subtasks failed")
		return nil, err
	}
	// merge task and subtask
	res := make([]task.Task, 0)
	for _, t := range tasks {
		tmpTask, err := transTask(&t)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("trans task err")
			continue
		}
		tmpSubtasks := make([]task.SubTask, 0)
		for _, n := range subtasks {
			if n.TaskId == t.ID {
				tmpSubtask := transSubTask(&n)
				tmpSubtasks = append(tmpSubtasks, *tmpSubtask)
			}
		}
		tmpTask.Scope.SubTasks = tmpSubtasks
		res = append(res, *tmpTask)
	}

	return res, nil
}

func init() {
	err := dequeue.Register(MockDbDequeueName, newMockDbDequeue)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("Name", MockDbDequeueName).Msg("int mock db dequeue err")
	}
}

func newMockDbDequeue(config dequeue.DequeueConfig) (dequeue.Dequeue, error) {
	d := &MockDbDequeue{}

	db, gormDb, err := store.NewPostgresDb(store.Host, store.Port, store.Username, store.Password)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("connect db err")
		return nil, err
	} else {
		logging.GetLogger().Info().Msg("connect db ok")
	}
	d.Db = db
	d.GormDb = gormDb

	return d, nil
}

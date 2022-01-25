package mock_dequeue

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dequeue"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	MockDequeueName = "mock-dequeue"
)

type MockDeqConfig struct {
	DequeNum int
}

type MockDequeue struct {
	config MockDeqConfig
}

var defaultSubtask = task.SubTask{
	ID:     0,
	TaskID: 0,
	Image: task.ImageInfo{
		ID:       1,
		RepoName: "nginx",
		Tag:      "1.20",
	},
	Registry: task.RegistryInfo{
		ID:       "registry-1",
		Username: "xxx",
		Password: "xxx",
		Secure:   false,
	},
}

func (d *MockDequeue) DequeueTasks(ctx context.Context) ([]task.Task, error) {
	// mock sub task
	subtasks := make([]task.SubTask, 0)
	st := defaultSubtask
	//st1 := task.SubTask{
	//	Id:     "sub-01",
	//	TaskId: "task-0",
	//	Image: task.ImageInfo{
	//		Id:       "image-1",
	//		RepoName: "redis",
	//		Tag:      "latest",
	//	},
	//	Registry: task.RegistryInfo{
	//		Id:       "registry-1",
	//		Username: "xxx",
	//		Password: "xxx",
	//		Secure:   false,
	//	},
	//}
	//st2 := task.SubTask{
	//	Id:     "sub-02",
	//	TaskId: "task-0",
	//	Image: task.ImageInfo{
	//		Id:       "image-1",
	//		RepoName: "ubuntu",
	//		Tag:      "18.04",
	//	},
	//	Registry: task.RegistryInfo{
	//		Id:       "registry-1",
	//		Username: "xxx",
	//		Password: "xxx",
	//		Secure:   false,
	//	},
	//}
	subtasks = append(subtasks, st)
	//subtasks = append(subtasks, st1)
	//subtasks = append(subtasks, st2)

	// test vuln scan
	scanType := make(map[task.ScanType]task.ScanPolicy)
	scanType[task.ScanType("scan-vuln")] = task.VulnPolicy{}
	scanType[task.ScanType("mock-scan-virus")] = task.MaliciousPolicy{}

	// mock task
	tasks := make([]task.Task, 0)
	t := task.Task{
		ID: 0,
		Scope: task.ScanScope{
			Type:     task.FullScan,
			SubTasks: subtasks,
		},
		ScanType: scanType,
		Trigger:  task.Trigger{Type: task.ManualTrigger},
		FlowConf: "mock-flow",
	}
	tasks = append(tasks, t)

	// another task
	st10 := defaultSubtask
	st10.TaskID = 1
	sts1 := make([]task.SubTask, 0)
	sts1 = append(sts1, st10)
	t1 := task.Task{
		ID: 1,
		Scope: task.ScanScope{
			Type:     task.FullScan,
			SubTasks: sts1,
		},
		ScanType: scanType,
		Trigger:  task.Trigger{Type: task.ManualTrigger},
		FlowConf: "mock-flow",
	}
	tasks = append(tasks, t1)

	return tasks, nil
}

func init() {
	err := dequeue.Register(MockDequeueName, newMockDequeue)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("Name", MockDequeueName).Msg("int mock dequeue err")
	}
}

func newMockDequeue(config dequeue.Config) (dequeue.Dequeue, error) {
	d := &MockDequeue{}

	return d, nil
}

package dequeuers

import (
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	imageModel "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

var (
	dequeues = map[DequeueType]Dequeue{}
)

type Dequeue interface {
	Type() DequeueType
	Pop() ([]imageModel.ScanSubTask, error)
}

func RegisterDequeuer(d Dequeue) {
	dequeues[d.Type()] = d
}

func PopTasks() ([]imageModel.ScanSubTask, error) {
	tasks := make([]imageModel.ScanSubTask, 0)
	for _, v := range dequeues {
		t, err := v.Pop()
		if err != nil {
			logging.GetLogger().Err(err).Str("dequeue", string(v.Type())).Msg("failed to pop tasks")
			continue
		}
		tasks = append(tasks, t...)
	}
	return tasks, nil
}

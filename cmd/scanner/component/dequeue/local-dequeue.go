package dequeue

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v2"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/queue"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	localDequeueName = "local-dequeue"
	DefaultDeqNum    = 10
)

type LocalDeqConfig struct {
	Que    *queue.Queue
	DeqNum int
}

type LocalDequeue struct {
	config LocalDeqConfig
}

func (l *LocalDequeue) DequeueTasks(ctx context.Context) ([]task.Task, error) {
	ts := make([]task.Task, 0)
	for i := 0; i < l.config.DeqNum; i++ {
		t, err := l.config.Que.Dequeue()
		if err != nil {
			return nil, fmt.Errorf("dequeue task err:%v", err)
		}
		ts = append(ts, t)
	}
	return ts, nil
}

func init() {
	err := Register(localDequeueName, newLocalDequeue)
	if err != nil {
		logging.GetLogger().Err(err).Str("Name", localDequeueName).Msg("int dequeue err")
	}
}

func newLocalDequeue(config Config) (Dequeue, error) {
	l := &LocalDequeue{}

	// parse config
	bytes, err := yaml.Marshal(config.Options)
	if err != nil {
		return nil, fmt.Errorf("db dequeuer: could not load configuration: %v", err)
	}
	err = yaml.Unmarshal(bytes, &l.config)
	if err != nil {
		return nil, fmt.Errorf("db dequeuer: could not load configuration: %v", err)
	}

	return l, nil
}

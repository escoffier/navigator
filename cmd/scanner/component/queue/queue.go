package queue

import (
	"github.com/oleiade/lane"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
)

type Queue struct {
	que     *lane.Queue
}

func NewQueue() *Queue {
	q := &Queue{
	}
	q.que = lane.NewQueue()
	return q
}

func (m *Queue) Enqueue(t *task.Task) error {
	m.que.Enqueue(*t)
	return nil
}

func (m *Queue) Dequeue() (task.Task,error) {
	item := m.que.Dequeue()
	t := item.(task.Task)
	return t,nil
}

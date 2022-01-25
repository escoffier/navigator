package dequeue

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dequeue"
	_ "gitlab.com/piccolo_su/vegeta/test/cmd/scanner/component/mock-dequeue"
	"testing"
)

func TestMockDequeue(t *testing.T) {
	deqName := "mock-dequeue"
	config := dequeue.Config{
		Type: deqName,
	}
	deq, err := dequeue.Open(config)
	if err != nil {
		t.Fatalf("get dequeue driver err.%v", err)
	}
	tasks, err := deq.DequeueTasks(context.Background())
	if err != nil {
		t.Fatalf("deq err:%v", err)
	}
	t.Logf("deq result:%+v", tasks)
}

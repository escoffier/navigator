package dequeue

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
)

type DequeueConfig struct {
	Type    string
	Options map[string]interface{}
}

var dequeues = make(map[string]Creator)

// Creator is a function that create job with specify config
type Creator func(config DequeueConfig) (Dequeue, error)

func Register(name string, creator Creator) error {
	if creator == nil {
		return errors.New("could not register nil Creator")
	}
	if _, dup := dequeues[name]; dup {
		return errors.New("could not register duplicate Creator: " + name)
	}
	dequeues[name] = creator
	return nil
}

// Open opens a registry specified by a configuration.
func Open(cfg DequeueConfig) (Dequeue, error) {
	driver, ok := dequeues[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Creator %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

// Dequeue interface defines the capabilities of task dequeuer
type Dequeue interface {
	DequeueTasks(ctx context.Context) ([]task.Task, error)
}

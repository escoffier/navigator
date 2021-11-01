package scan

import (
	"context"
	"errors"
	"fmt"
)

type Param map[string]interface{}

type Artifact map[string]interface{}

type ExecutorConfig struct {
	Type   string
	Policy interface{}
}

var executors = make(map[string]Creator)

// Creator is a function that create job with specify config
type Creator func(config ExecutorConfig) (Executor, error)

// Register makes a Constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, creator Creator) error {
	if creator == nil {
		return errors.New("could not register nil Creator")
	}
	if _, dup := executors[name]; dup {
		return errors.New("could not register duplicate Creator: " + name)
	}
	executors[name] = creator
	return nil
}

// Open opens a registry specified by a configuration.
func Open(cfg ExecutorConfig) (Executor, error) {
	driver, ok := executors[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Creator %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

// Executor represents the required operations of an executor
type Executor interface {
	Scan(ctx context.Context, param Param) (Artifact, error)
}

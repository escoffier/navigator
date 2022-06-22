package dp

import (
	"errors"
	"fmt"
	// "gitlab.com/security-rd/go-pkg/logging"
)

type ExecutorConfig struct {
	Type string
	Run  map[string]interface{}
}

type Creator func(config ExecutorConfig) (Executor, error)

var executors = make(map[string]Creator)

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

func Open(cfg ExecutorConfig) (Executor, error) {
	driver, ok := executors[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Creator %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

type Executor interface {
	Run() error
}

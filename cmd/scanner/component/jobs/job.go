package jobs

import (
	"context"
	"errors"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
)

// Artifact define job's output
type Artifact map[string]interface{}

// Param job's input parameter
type Param map[string]interface{}

type JobInfo struct {
	Task    task.Task
	SubTask task.SubTask
	// cache server url
	CacheServerURL string
}

// JobConfig is a configuration block that can be used to
// determine which job should be initialized and pass custom
// configuration to it.
type JobConfig struct {
	Type string
	Info JobInfo
}

var jobs = make(map[string]Creator)

// Creator is a function that create job with specify config
type Creator func(JobConfig) (Job, error)

// Register makes a Constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, creator Creator) error {
	if creator == nil {
		return errors.New("could not register nil Creator")
	}
	if _, dup := jobs[name]; dup {
		return errors.New("could not register duplicate Creator: " + name)
	}
	jobs[name] = creator
	return nil
}

// Open opens a registry specified by a configuration.
func Open(cfg JobConfig) (Job, error) {
	driver, ok := jobs[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Creator %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

// Job represents the required operations of a job
type Job interface {
	Run(ctx context.Context, param Param) (Artifact, error)
}

func DumpJobs() {
	fmt.Printf("all jobs:\n")
	for k := range jobs {
		fmt.Printf("%s ", k)
	}
	fmt.Println()
}

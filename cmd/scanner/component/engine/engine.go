package engine

import "context"

// LoopEngineFunc a function will be run in every event loop
type LoopEngineFunc func(interface{}) error

// Engine interface defines the workflow engine
type Engine interface {
	Run(ctx context.Context) error
}

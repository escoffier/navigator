package cri

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
)

type Runtime interface {
	InspectImage(ctx context.Context, ns, imageID string) (types.ImageInspect, error)
	ImageLayers(ctx context.Context, ns, imageID string) ([]image.HistoryResponseItem, error)
	Info() (types.Info, error)
	Type() string
}

type RuntimeConfig struct {
	Type    string
	Options map[string]interface{}
}

var drivers = make(map[string]Driver)

type Driver func(runtime RuntimeConfig) (Runtime, error)

func Register(name string, driver Driver) error {
	if driver == nil {
		return fmt.Errorf("could not register nil dirver")
	}
	if _, dup := drivers[name]; dup {
		return fmt.Errorf("could not register duplicate Driver: " + name)
	}
	drivers[name] = driver
	return nil
}

func Open(cfg RuntimeConfig) (Runtime, error) {
	driver, ok := drivers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Driver %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

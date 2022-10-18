package container

import (
	"fmt"

	"github.com/docker/docker/api/types"
)

type EventMessage struct {
	Event string // start
	Type  string // container,network,etc.
	//ContainerID   string
	//ProcessID     int
	//ImageID       string   // eg: sha256:ebxxx,not manifest
	//ImageRepoTags []string // eg: [library/nginx:1.20,dev/nginx:1.20]
	Time          int64
	ContainerInfo ContainerMeta
}

type ContainerMeta struct {
	ID        string
	Name      string
	ProcessID int
	ImageID   string

	// [sha256:xxx,sha256:yyy].for manifestv1, image digest could be different depend on registry.
	// but the image content is same
	ImageDigest []string
	State       string

	// one image may have different repo tags
	// eg:[library/nginx:1.20,dev/nginx:1.20]
	ImageRepoTags []string

	PodUID string
}

type EventCallback func(*EventMessage)

type Runtime interface {
	MonitorEvent(cb EventCallback) error
	StopMonitorEvent() error
	GetContainerMeta(containerID string) (ContainerMeta, error)
	ListRunningContainers() ([]types.Container, error)
	ListImages() ([]types.ImageSummary, error)
	GetContainerInspect(containerID string) (types.ContainerJSON, error)
	GetImageInspect(imageID string) (types.ImageInspect, error)
	RuntimeInfo() (types.Info, error)
	SaveImage(imageID, fullPath string) (string, error)
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

package container

import (
	"fmt"
	"github.com/docker/docker/api/types"
)

var (
	defaultDockerSocket string = "unix:///host/var/run/docker.sock"
)

type EventMessage struct {
	Event         string // start
	Type          string // container,network,etc.
	Time          int64
	ContainerInfo ContainerMeta
}

type ContainerMeta struct {
	ID        string
	Namespace string
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

	PodUID      string
	GraphDriver types.GraphDriverData // storage layer info
	Labels      map[string]string     // List of labels set to this container
}

func (c *ContainerMeta) PodNamespace() string {
	for k, v := range c.Labels {
		if k == "io.kubernetes.pod.namespace" {
			return v
		}
	}
	return ""
}

type EventCallback func(*EventMessage)

type Runtime interface {
	MonitorEvent(cb EventCallback) error
	StopMonitorEvent() error
	GetContainerMeta(namespace string, containerID string) (ContainerMeta, error)
	ListRunningContainers() ([]Container, error)
	ListImages() ([]ImageSummary, error)
	GetContainerInspect(containerID string) (ContainerInspect, error)
	GetImageInspect(namespace string, imageID string) (ImageInspect, error)
	ImageHistory(namespace string, imageID string) ([]HistoryResponseItem, error)
	RuntimeInfo() (RuntimeInfo, error)
	SaveImage(namespace, imageID, fullPath string) (string, error)
	// GetImageLayersDir 获取镜像文件内容
	//isTmpDir：是否是临时目录，如果是，使用后请手动删除
	GetImageLayersDir(namespace, imageId string) (layerDirs []string, isTmpDir bool, err error)
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

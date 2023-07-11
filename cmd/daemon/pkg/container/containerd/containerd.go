package containerd

import (
	"github.com/containerd/containerd"
	types2 "github.com/docker/docker/api/types"
	dockerImage "github.com/docker/docker/api/types/image"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"

	// "io"
	"os"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/security-rd/go-pkg/logging"
)

// todo 待实现
const (
	version                  = "containerd"
	containerdRequestTimeout = 20
	exportImageTimeout       = 1800 // long timeout for big image
	imageTarTimeoutENV       = "IMG_TAR_TIMEOUT_ENV"
)

type containerdDriverConfig struct {
	Endpoint string `json:"endpoint"`
}

type containerdDriver struct {
	config        *containerdDriverConfig
	evCallback    container.EventCallback
	containerdCli *containerd.Client
}

func (c *containerdDriver) MonitorEvent(cb container.EventCallback) error {

	//TODO implement me
	//panic("implement me")
	return nil
}

func (c *containerdDriver) StopMonitorEvent() error {
	//TODO implement me
	//panic("implement me")
	return nil
}

func (c *containerdDriver) GetContainerMeta(containerID string) (container.ContainerMeta, error) {
	//TODO implement me
	//panic("implement me")
	return container.ContainerMeta{}, nil
}

func (c *containerdDriver) ListRunningContainers() ([]types2.Container, error) {
	//TODO implement me
	//panic("implement me")
	return nil, nil
}

func (c *containerdDriver) ListImages() ([]types2.ImageSummary, error) {
	//TODO implement me
	//panic("implement me")
	return nil, nil
}

func (c *containerdDriver) GetContainerInspect(containerID string) (types2.ContainerJSON, error) {
	//TODO implement me
	//panic("implement me")
	return types2.ContainerJSON{}, nil
}

func (c *containerdDriver) GetImageInspect(imageID string) (types2.ImageInspect, error) {
	//TODO implement me
	//panic("implement me")
	return types2.ImageInspect{}, nil
}

func (c *containerdDriver) ImageHistory(imageID string) ([]dockerImage.HistoryResponseItem, error) {
	//TODO implement me
	//panic("implement me")
	return nil, nil
}

func (c *containerdDriver) RuntimeInfo() (types2.Info, error) {
	//TODO implement me
	//panic("implement me")
	return types2.Info{}, nil
}

func (c *containerdDriver) SaveImage(imageID, fullPath string) (string, error) {
	//TODO implement me
	//panic("implement me")
	return "", nil
}

func init() {
	err := container.Register(version, NewcontainerdDriver)
	if err != nil {
		logging.Get().Err(err).Msg("register runtime containerd driver failed")
		return
	}

	logging.Get().Debug().Msg("runtime containerd driver register success")
}

func NewcontainerdDriver(config container.RuntimeConfig) (container.Runtime, error) {
	var d containerdDriver

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.Get().
			Err(err).
			Interface("options", config.Options).
			Msg("runtime containerd marshal config failed")
		return nil, err
	}

	conf := new(containerdDriverConfig)
	if err := json.Unmarshal(byt, conf); err != nil {
		logging.Get().
			Err(err).
			Bytes("config", byt).
			Msg("runtime containerd Unmarshal config failed")
		return nil, err
	}

	d.config = conf
	d.config.Endpoint = strings.TrimSpace(d.config.Endpoint)
	if d.config.Endpoint != "" {
		os.Setenv("containerd_HOST", d.config.Endpoint)
	}
	uri := nodeinfo.GetContainerdAddr()
	//containerd client
	containerdCli, err := containerd.New(strings.TrimPrefix(uri, "unix://"), containerd.WithTimeout(time.Duration(5*time.Second)))
	if err != nil {
		logging.Get().
			Err(err).
			Msg("create containerd client failed")
		return nil, err
	}

	d.containerdCli = containerdCli

	return &d, nil
}

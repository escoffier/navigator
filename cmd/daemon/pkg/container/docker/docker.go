package docker

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	version              = "docker"
	dockerRequestTimeout = 3
)

type dockerDriverConfig struct {
	Endpoint string `json: "endpoint"`
}

type dockerDriver struct {
	config     *dockerDriverConfig
	evCallback container.EventCallback
	dockerCli  *client.Client
}

func (d *dockerDriver) GetContainerMeta(containerID string) (container.ContainerMeta, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerRequestTimeout*time.Second)
	defer cancel()
	c, err := d.dockerCli.ContainerInspect(ctx, containerID)
	if err != nil {
		return container.ContainerMeta{}, fmt.Errorf("container inspect failed, %v", err)
	}

	// logging.Get().Debug().Interface("containerJson", c).Msg("docker inspect container")
	if c.State.Pid <= 0 {
		return container.ContainerMeta{}, fmt.Errorf("get container's pid failed, pid : %v", c.State.Pid)
	}
	cm := &container.ContainerMeta{}
	cm.ProcessID = c.State.Pid
	cm.ImageID = c.Image
	cm.ID = c.ID
	cm.Name = c.Name
	cm.State = c.State.Status

	labels := c.Config.Labels
	for k, v := range labels {
		if k == "io.kubernetes.pod.uid" {
			cm.PodUID = v
			break
		}
	}
	if cm.PodUID == "" {
		return *cm, fmt.Errorf("get container's pod uid failed, pod uid : %v", cm.PodUID)
	}

	// inspect image info
	image, _, err := d.dockerCli.ImageInspectWithRaw(ctx, c.Image)
	if err != nil {
		return *cm, fmt.Errorf("image inspect failed.%v", err)
	}

	// RepoDigests eg: ["library/deploy@sha256:26b1xxx","quay.io/test/dev@sha256:3445xxx"]
	// modify to: ["sha256:26b1xxx","sha256:3445xxx"]
	tmpDigests := make(map[string]int)
	for _, v := range image.RepoDigests {
		arr := strings.Split(v, "@")
		if len(arr) != 2 {
			logging.Get().Warn().Str("containerID", containerID).Str("repoDigest", v).Msg("wrong format,ignore")
			continue
		}

		// remove duplicate digest
		ds := arr[1]
		_, ok := tmpDigests[ds]
		if ok {
			continue
		}
		tmpDigests[ds] = 1
		cm.ImageDigest = append(cm.ImageDigest, ds)
	}

	cm.ImageRepoTags = image.RepoTags

	return *cm, nil
}

func (d *dockerDriver) MonitorEvent(cb container.EventCallback) error {
	logging.Get().Debug().Msg("docker start monitor events")

	filter := filters.NewArgs(
		filters.Arg("event", "start"), // not "create"
		filters.Arg("event", "kill"),
		filters.Arg("type", "container"),
	)

	msg, errs := d.dockerCli.Events(context.Background(), types.EventsOptions{
		Filters: filter,
	})

	for {
		select {
		case m := <-msg:
			logging.Get().Debug().Interface("msg", m).Msg("receive docker event")

			ev, err := d.transformEvent(&m)
			if err != nil {
				logging.Get().Err(err).Msg("transform docker event msg failed")
			} else {
				cb(ev)
			}
		case err := <-errs:
			if err != nil {
				logging.Get().Err(err).Msg("docker events err. try to restart")
				// todo: restart after reach err-num upperbound
				// try to restart listening to container streams
				msg, errs = d.dockerCli.Events(context.Background(), types.EventsOptions{
					Filters: filter,
				})
			}
		}
	}
}

func (d *dockerDriver) StopMonitorEvent() error {
	return nil
}

// ListImages : list all exist images
func (d *dockerDriver) ListImages() ([]types.ImageSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerRequestTimeout*time.Second)
	defer cancel()
	images, err := d.dockerCli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list images failed:%v", err)
	}
	return images, nil
}

// ListRunningContainers : list all exist containers
func (d *dockerDriver) ListRunningContainers() ([]types.Container, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerRequestTimeout*time.Second)
	defer cancel()
	filter := filters.NewArgs(
		filters.Arg("status", "running"),
	)

	containers, err := d.dockerCli.ContainerList(ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		return nil, fmt.Errorf("list containers failed, %v", err)
	}
	//logging.Get().Debug().Interface("containers", containers).Msg("list containers")
	return containers, nil
}

func (d *dockerDriver) GetImageInspect(imageID string) (types.ImageInspect, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerRequestTimeout*time.Second)
	defer cancel()
	image, _, err := d.dockerCli.ImageInspectWithRaw(ctx, imageID)
	if err != nil {
		return types.ImageInspect{}, fmt.Errorf("get image inspect failed, %v", err)
	}
	return image, nil
}

func (d *dockerDriver) GetContainerInspect(containerID string) (types.ContainerJSON, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerRequestTimeout*time.Second)
	defer cancel()
	ci, err := d.dockerCli.ContainerInspect(ctx, containerID)
	if err != nil {
		logging.Get().Err(err).Str("containerID", containerID).Msg("inspect container failed")
		return types.ContainerJSON{}, err
	}
	return ci, nil
}

func init() {
	err := container.Register(version, NewDockerDriver)
	if err != nil {
		logging.Get().Err(err).Msg("register runtime docker driver failed")
		return
	}

	logging.Get().Debug().Msg("runtime docker driver register success")
}

func NewDockerDriver(config container.RuntimeConfig) (container.Runtime, error) {
	var d dockerDriver

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.Get().
			Err(err).
			Interface("options", config.Options).
			Msg("runtime docker marshal config failed")
		return nil, err
	}

	conf := new(dockerDriverConfig)
	if err := json.Unmarshal(byt, conf); err != nil {
		logging.Get().
			Err(err).
			Bytes("config", byt).
			Msg("runtime docker Unmarshal config failed")
		return nil, err
	}

	d.config = conf
	d.config.Endpoint = strings.TrimSpace(d.config.Endpoint)
	if d.config.Endpoint != "" {
		os.Setenv("DOCKER_HOST", d.config.Endpoint)
	}
	uri := os.Getenv("DOCKER_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/docker.sock"
	}

	//docker client
	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithHost(uri))
	if err != nil {
		logging.Get().
			Err(err).
			Msg("create docker client failed")
		return nil, err
	}
	d.dockerCli = dockerCli

	return &d, nil
}

func (d *dockerDriver) transformEvent(ev *events.Message) (*container.EventMessage, error) {
	msg := &container.EventMessage{
		Type:  ev.Type,
		Event: ev.Action,
		Time:  ev.Time,
	}
	containerInfo, err := d.GetContainerMeta(ev.ID)
	if err != nil {
		return nil, fmt.Errorf("get container info failed:%v", err)
	}
	msg.ContainerInfo = containerInfo

	return msg, nil
}

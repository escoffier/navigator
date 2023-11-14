package containerd

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/events/exchange"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/typeurl"
	types2 "github.com/docker/docker/api/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/docker"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"os"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/security-rd/go-pkg/logging"
)

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

	newExchange := exchange.NewExchange()
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	filters := []string{
		`topic=="/tasks/start"`,
		`topic=="/tasks/delete"`,
	}

	msg, errs := c.containerdCli.Subscribe(ctx, filters...)
	for {
		select {
		case m := <-msg:
			go func() {
				logging.Get().Info().Msgf("containerd received event ,topic:%s,namespace:%s", m.Topic, m.Namespace)
				v, err := typeurl.UnmarshalAny(m.Event)
				if err != nil {
					logging.Get().Err(err).Any("event", m).Msg("failed to unmarshal event")
					return
				}
				var containerId string
				action := ""
				switch t := v.(type) {
				case *events.TaskStart:
					containerId = t.ContainerID
					action = "start"
				case *events.TaskDelete:
					containerId = t.ContainerID
					action = "delete"
				default:
					logging.Get().Error().Msgf("containerd ignore event, namespace:%s,topic:%s,event:%s", m.Namespace, m.Topic, m.Event.GetTypeUrl())
					return
				}
				ev := &container.EventMessage{
					Type:  "container",
					Event: action,
					Time:  m.Timestamp.Unix(),
				}
				containerInfo, err := c.GetContainerMeta(m.Namespace, containerId)
				ev.ContainerInfo = containerInfo
				if err != nil && !errors.Is(err, container.ErrNotFoundPodID) {
					logging.Get().Err(err).Msg("transform containerd event msg failed")
				} else {
					cb(ev)
				}
			}()
		case err := <-errs:
			if err != nil {
				logging.Get().Err(err).Msgf("err returned for containerd events. try to restart")
				// try to restart listening to container streams
				msg, errs = newExchange.Subscribe(ctx)
			}
		}
	}
}

func (c *containerdDriver) StopMonitorEvent() error {
	return nil
}

func (c *containerdDriver) GetContainerMeta(namespace string, containerID string) (container.ContainerMeta, error) {
	if containerID == "" {
		return container.ContainerMeta{}, fmt.Errorf("containerID is empty")
	}
	var contain containerd.Container
	if namespace == "" {
		// walk all namespace
		namespaceList, err := c.containerdCli.NamespaceService().List(context.Background())
		if err != nil {
			return container.ContainerMeta{}, fmt.Errorf("list ns failed,%v", err)
		}
		for _, ns := range namespaceList {
			ctx, cancel := context.WithTimeout(context.Background(), containerdRequestTimeout*time.Second)
			defer cancel()
			nsCtx := namespaces.WithNamespace(ctx, ns)
			_, err := c.containerdCli.LoadContainer(nsCtx, containerID)
			if err != nil {
				continue
			} else {
				namespace = ns
				break
			}
		}
	}
	if namespace == "" {
		return container.ContainerMeta{}, fmt.Errorf("container not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), containerdRequestTimeout*time.Second)
	defer cancel()
	nsCtx := namespaces.WithNamespace(ctx, namespace)
	contain, err := c.containerdCli.LoadContainer(nsCtx, containerID)
	if err != nil {
		return container.ContainerMeta{}, fmt.Errorf("LoadContainer failed,%v", err)
	}
	info, err := contain.Info(nsCtx)
	if err != nil {
		return container.ContainerMeta{}, fmt.Errorf("get container info failed.%v", err)
	}
	logging.Get().Debug().Msgf("info.Labels :%v", info.Labels)
	t, err := contain.Task(nsCtx, nil)
	if err != nil {
		return container.ContainerMeta{}, fmt.Errorf("get container task failed.%v", err)
	}
	status, err := t.Status(nsCtx)
	if err != nil {
		return container.ContainerMeta{}, fmt.Errorf("get container Status failed.%v", err)
	}
	image, err := contain.Image(nsCtx)
	if err != nil {
		return container.ContainerMeta{}, fmt.Errorf("get containerd's image failed. %v", err)
	}

	meta := container.ContainerMeta{
		ID:            info.ID,
		Namespace:     namespace,
		Name:          info.Labels["io.kubernetes.container.name"],
		ProcessID:     int(t.Pid()),
		ImageID:       image.Name(),
		ImageDigest:   []string{image.Target().Digest.String()},
		State:         string(status.Status),
		ImageRepoTags: nil,
		GraphDriver:   types2.GraphDriverData{},
		Labels:        info.Labels,
	}
	// get pod id
	meta.PodUID = info.Labels["io.kubernetes.pod.uid"]
	if meta.PodUID == "" {
		return meta, container.ErrNotFoundPodID
	}

	return meta, nil
}

func (c *containerdDriver) ListRunningContainers() ([]container.Container, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runningContainers []container.Container

	namespaceList, err := c.containerdCli.NamespaceService().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list ns failed,%v", err)
	}
	for _, namespace := range namespaceList {
		nsCtx := namespaces.WithNamespace(ctx, namespace)
		tasksResponse, err := c.containerdCli.TaskService().List(nsCtx, &tasks.ListTasksRequest{Filter: `status=="running"`})
		if err != nil {
			logging.Get().Err(err).Msg("get taskList failed .")
		}
		for _, t := range tasksResponse.Tasks {
			if t.ContainerID == "" {
				t.ContainerID = t.ID
			}
			contain, err := c.containerdCli.LoadContainer(nsCtx, t.ContainerID)
			if err != nil {
				logging.Get().Err(err).Msg("get container failed.")
				continue
			}
			info, err := contain.Info(nsCtx)
			if err != nil {
				logging.Get().Err(err).Msg("get container info failed.")
				continue
			}
			labels := info.Labels
			if labels != nil && labels["io.cri-containerd.kind"] == "sandbox" {
				logging.Get().Info().Msgf("skip sandbox container,containerId:%s", info.ID)
				continue
			}
			spec, err := contain.Spec(nsCtx)
			if err != nil {
				logging.Get().Err(err).Msg("get container spec failed.")
				continue
			}
			runningContainers = append(runningContainers, container.Container{
				ID:        info.ID,
				Namespace: namespace,
				Names:     []string{info.ID},
				Image:     info.Image,
				ImageID:   info.Image,
				Command:   strings.Join(spec.Process.Args, " "),
				Created:   info.CreatedAt.Unix(),
				Labels:    info.Labels,
				Status:    c.getContainerStatus(t.Status),
			})
		}
	}
	return runningContainers, nil
}

// containerD Status To assets Status
func (c *containerdDriver) getContainerStatus(state task.Status) string {
	// github.com/containerd/containerd@v1.5.16/api/types/task/task.pb.go:33
	switch int32(state) {
	case 0:
		return assets.GetRawContainerStatus(assets.Dead)
	case 1:
		return assets.GetRawContainerStatus(assets.Created)
	case 2:
		return assets.GetRawContainerStatus(assets.Running)
	case 3:
		return assets.GetRawContainerStatus(assets.Exited)
	case 4, 5:
		return assets.GetRawContainerStatus(assets.Paused)
	default:
		return assets.GetRawContainerStatus(assets.Dead)
	}
}

func (c *containerdDriver) ListImages() ([]container.ImageSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), containerdRequestTimeout*time.Second)
	defer cancel()
	list, err := c.containerdCli.NamespaceService().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("get nsList failed.%v", err)
	}
	var imageList []container.ImageSummary
	for _, ns := range list {
		nsCtx := namespaces.WithNamespace(ctx, ns)
		images, err := c.containerdCli.ListImages(nsCtx)
		if err != nil {
			continue
		}
		for _, image := range images {
			imageList = append(imageList, container.ImageSummary{
				Namespace:   ns,
				ID:          image.Name(),
				Labels:      image.Labels(),
				RepoTags:    []string{image.Name()},
				RepoDigests: []string{image.Target().Digest.String()},
			})
		}
	}
	return imageList, nil
}

func (c *containerdDriver) GetContainerInspect(containerID string) (container.ContainerInspect, error) {
	// TODO implement me
	return container.ContainerInspect{}, nil
}

func (c *containerdDriver) GetImageInspect(namespace string, imageID string) (container.ImageInspect, error) {
	ctx, cancel := context.WithTimeout(context.Background(), containerdRequestTimeout*time.Second)
	defer cancel()
	nsCtx := namespaces.WithNamespace(ctx, namespace)
	image, err := c.containerdCli.GetImage(nsCtx, imageID)
	if err != nil {
		return container.ImageInspect{}, fmt.Errorf("get imageInspect failed,%v", err)
	}

	configDesc, err := image.Config(nsCtx)
	if err != nil {
		return container.ImageInspect{}, fmt.Errorf("get image config failed,%v", err)
	}
	p, err := content.ReadBlob(nsCtx, image.ContentStore(), configDesc)
	if err != nil {
		return container.ImageInspect{}, fmt.Errorf("read image blob failed,%v", err)
	}
	var config ocispec.Image
	if err := json.Unmarshal(p, &config); err != nil {
		return container.ImageInspect{}, fmt.Errorf("unmarshal imageconfig failed,%v", err)
	}
	var fs container.RootFS
	fs.Type = config.RootFS.Type
	for _, d := range config.RootFS.DiffIDs {
		fs.Layers = append(fs.Layers, string(d))
	}
	split := strings.Split(image.Name(), "@")
	var repoDigest string
	if len(split) == 2 {
		repoDigest = image.Name()
	} else {
		split = strings.Split(image.Name(), ":")
		if len(split) == 2 {
			repoDigest = split[0] + "@" + image.Target().Digest.String()
		}
	}

	result := container.ImageInspect{
		Namespace:    namespace,
		ID:           image.Name(),
		RepoTags:     []string{image.Name()},
		RepoDigests:  []string{repoDigest},
		Env:          config.Config.Env,
		Cmd:          config.Config.Cmd,
		User:         config.Config.User,
		Architecture: config.Architecture,
		Variant:      config.Variant,
		Os:           config.OS,
		OsVersion:    config.OSVersion,
		Size:         image.Target().Size,
		VirtualSize:  image.Target().Size,
		RootFS:       fs,
	}
	return result, nil
}

func (c *containerdDriver) ImageHistory(namespace string, imageID string) ([]container.HistoryResponseItem, error) {
	ctx, cancel := context.WithTimeout(context.Background(), containerdRequestTimeout*time.Second)
	defer cancel()
	nsCtx := namespaces.WithNamespace(ctx, namespace)
	image, err := c.containerdCli.GetImage(nsCtx, imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to get image , %v", err)
	}
	configDesc, err := image.Config(nsCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image config, %v", err)
	}
	p, err := content.ReadBlob(nsCtx, image.ContentStore(), configDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to get read image blob, %v", err)
	}
	var config ocispec.Image
	if err := json.Unmarshal(p, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal image config, %v", err)
	}
	var historyList []container.HistoryResponseItem
	for _, history := range config.History {
		h := container.HistoryResponseItem{
			Comment:   history.Comment,
			Created:   history.Created.Unix(),
			CreatedBy: history.CreatedBy,
			// ID:        "",
			// Size:      0,
			// Tags:      nil,
		}
		historyList = append(historyList, h)
	}
	return historyList, nil
}

// TODO fix
func (c *containerdDriver) RuntimeInfo() (container.RuntimeInfo, error) {
	return container.RuntimeInfo{
		RuntimeType:  version,
		RootDir:      "/var/lib/containerd",
		Driver:       "image-tar",
		DriverStatus: nil,
	}, nil
}

func isTarFile(filename string) bool {
	f, err := os.Open(filename)
	if err != nil {
		logging.Get().Err(err).Str("filename", filename).Msg("open file failed")
		return false
	}
	defer f.Close()

	tr := tar.NewReader(f)

	_, err = tr.Next()

	return err == nil
}

func (c *containerdDriver) SaveImage(namespace, imageID, fullPath string) (string, error) {
	exportTimeout := exportImageTimeout
	timeout := os.Getenv(imageTarTimeoutENV)
	if len(timeout) > 0 {
		tmpTimeout, err := strconv.Atoi(timeout)
		if err != nil {
			logging.Get().Warn().Str("imageTarTimeoutEnv", timeout).Msg("timeout env not int,set default timeout")
		} else {
			exportTimeout = tmpTimeout
		}
	}
	logging.Get().Debug().Int("imageExportTimeout", exportTimeout).Msg("save image set time out")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(exportTimeout)*time.Second)
	defer cancel()
	nsCtx := namespaces.WithNamespace(ctx, namespace)
	md5Str := util.MD5Hex(namespace + imageID)
	// todo tmp
	tmpFilePath := filepath.Join("/tmp/", md5Str)
	logging.Get().Debug().Str("tmpFilePath", tmpFilePath).Msg("save image")
	file, err := os.OpenFile(tmpFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		return "", fmt.Errorf("open file failed ,path:%s ,err:%v", tmpFilePath, err)
	}
	err = c.containerdCli.Export(nsCtx, file, archive.WithImage(c.containerdCli.ImageService(), imageID), archive.WithPlatform(platforms.DefaultStrict()))
	if err != nil {
		logging.Get().Err(err).Msg("failed to export image")
		return "", fmt.Errorf("export containerd image failed,err:%v", err)
	}
	if err = file.Close(); err != nil {
		logging.Get().Err(err).Msg("failed to close tmpFile,path:" + tmpFilePath)
	}

	file, err = os.Open(tmpFilePath)
	defer func() {
		file.Close()
		if err = os.Remove(tmpFilePath); err != nil {
			logging.Get().Err(err).Msg("failed to remove tmpFile,path:" + tmpFilePath)
		}
	}()
	if err = docker.UnTar(file, fullPath); err != nil {
		return "", err
	}

	// example dir tree
	// # tree ./
	// ./
	// ├── blobs
	// │   └── sha256
	// │       ├── 0bced47fffa3361afa981854fcabcd4577cd43cebbb808cea2b1f33a3dd7f508 gzip compressed data, original size modulo 2^32 7168
	// │       ├── 3153aa388d026c26a2235e1ed0163e350e451f41a8a313e1804d7e1afb857ab4 JSON data
	// │       ├── 5a81c4b8502e4979e75bd8f91343b95b0d695ab67f241dbed0d1530a35bde1eb gzip compressed data, original size modulo 2^32 7168
	// │       └── b060fffe8e1561c9c3e6dea6db487b900100fc26830b9ea2ec966c151ab4c020 JSON data
	// ├── index.json
	// ├── manifest.json
	// └── oci-layout
	// 2 directories, 7 files

	return fullPath, nil
}

func (c *containerdDriver) GetImageLayersDir(namespace, imageId string) (layerDirs []string, err error) {
	// TODO implement me
	panic("implement me")
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
	// containerd client
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

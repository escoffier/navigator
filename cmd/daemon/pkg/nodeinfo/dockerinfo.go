package nodeinfo

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/docker/pkg/stringid"

	"github.com/docker/docker/api/types/events"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/logging"
)

var _ ContainerInfoManager = (*DockerInfoManager)(nil)

const (
	containerIDTimeoutSec = int64(90)
)

type DockerInfoManager struct {
	dockerCli     *client.Client
	hostIP        string
	hostName      string
	containerData map[string]int64 // map[containerId]time
	handlers      []ContainerEventHandler
	agent         *containerassets.Agent
	store         containerassets.PodCache
	clusterKey    string
	mqReady       atomic.Bool
	sync.RWMutex
	retryMap     map[string]*dockerRetryItem
	retryMapLock *sync.Mutex
	synced       atomic.Bool
}

// Synced implements ContainerInfoManager.
func (d *DockerInfoManager) Synced() bool {
	return d.synced.Load()
}

type dockerRetryItem struct {
	containerId string
	outTime     time.Time
}

func (d *DockerInfoManager) SetPodStore(store containerassets.PodCache) {
	d.store = store
}

func (d *DockerInfoManager) AddEventHandler(handler ContainerEventHandler) {
	d.handlers = append(d.handlers, handler)
}

func NewDockerInfoManager(clusterKey, hostName, hostIP string, agent *containerassets.Agent) (*DockerInfoManager, error) {
	uri := os.Getenv("DOCKER_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/docker.sock"
	}

	// docker client
	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithHost(uri), client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, errors.Errorf("docker new client failed, %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = dockerCli.Ping(ctx)
	if err != nil {
		return nil, errors.Errorf("ping docker server failed, %v", err)
	}

	dockerCli.NegotiateAPIVersion(ctx)

	rs := DockerInfoManager{
		dockerCli:     dockerCli,
		hostIP:        hostIP,
		hostName:      hostName,
		containerData: make(map[string]int64, 30),
		clusterKey:    clusterKey,
		agent:         agent,
		retryMap:      make(map[string]*dockerRetryItem),
		retryMapLock:  new(sync.Mutex),
	}
	rs.mqReady.Store(false)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		rs.clearContainerTimeoutData()
	}()
	go func() {
		defer func() {
			r := recover()
			if r != nil {
				logging.Get().Error().Str("CRI", ContainerdType).Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		rs.Retry()
	}()
	return &rs, nil
}

func (d *DockerInfoManager) clearContainerTimeoutData() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	count := 0
	for now := range ticker.C {
		func(nowTime time.Time) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()

			d.Lock()
			defer d.Unlock()

			if count >= 60 { // if a map keeps a stable size but is with continuous add or delete, it should be reconstructed after a period of time to prevent memory leak
				newMap := make(map[string]int64, len(d.containerData))
				for containerID, timestamp := range d.containerData {
					if nowTime.Unix()-timestamp >= containerIDTimeoutSec {
						continue
					}
					newMap[containerID] = timestamp
				}
				d.containerData = newMap
				count = 0
			} else {
				for containerID, timestamp := range d.containerData {
					if nowTime.Unix()-timestamp < containerIDTimeoutSec {
						continue
					}
					delete(d.containerData, containerID)
				}
				count++
			}

		}(now)
	}
}

func (d *DockerInfoManager) GetContainerPid(containerID string) (int, string, error) {
	if containerID == "" {
		return 0, "", fmt.Errorf("container ID is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	id := strings.TrimPrefix(containerID, "docker://")
	container, err := d.dockerCli.ContainerInspect(ctx, id)
	if err != nil {
		return 0, "", fmt.Errorf("container inspace failed, %v", err)
	}

	if container.State.Pid <= 0 {
		return 0, "", fmt.Errorf("get container's pid failed, pid : %v", container.State.Pid)
	}

	return container.State.Pid, id, nil
}

func (d *DockerInfoManager) ListenEvents(saveData SaveContainerDataFunc) {
	// https://docs.docker.com/engine/reference/commandline/events/
	filter := filters.NewArgs(
		// filters.Arg("event", "create"),
		filters.Arg("event", "start"),
		// filters.Arg("event", "restart"),
		// filters.Arg("event", "rename"),
		// filters.Arg("event", "resize"),
		filters.Arg("event", "stop"),
		filters.Arg("event", "destroy"),
		filters.Arg("type", "container"),
	)

	logging.Get().Info().Str("raw-container", "ListenEvents").Msg("begin to listen events from docker")

	msg, errs := d.dockerCli.Events(context.Background(), types.EventsOptions{
		Filters: filter,
	})

	for {
		select {
		case m := <-msg:
			go func() {
				//if m.Action == "start" {
				//	//todo  新增事件，延迟1秒处理，ports和进程
				//	time.Sleep(time.Second)
				//}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()

				logging.Get().Debug().Msgf("raw-container - received event from docker %+v", m)
				saveData(m.ID, m.Time)
				if d.mqReady.Load() {
					if m.Actor.Attributes["io.kubernetes.docker.type"] == "podsandbox" {
						logging.Get().Debug().Msgf("skip podsandbox container")
						return
					}
					if ExportRawContainer {
						container := d.containerFromEvent(m)
						if m.Action != "stop" && m.Action != "destroy" {
							container = d.updateContainerDetail(ctx, container)
						} else {
							container.LastStopTime = time.Unix(m.Time, 0)
						}
						if m.Action == "start" && len(container.Ports) == 0 {
							//	 If the container port is empty, try again after 1 minute
							d.addRetryContainer(container.ContainerID)
						}
						d.processEvents(ctx, container, m.Action)
					}
				}
			}()
		case err := <-errs:
			if err != nil {
				logging.Get().Err(err).Msgf("err returned for docker events. try to restart")
				// try to restart listening to container streams
				msg, errs = d.dockerCli.Events(context.Background(), types.EventsOptions{
					Filters: filter,
				})
			}
		}
	}
}

func (d *DockerInfoManager) Start() error {
	t := time.Now()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		if ExportRawContainer {
			// check if mq ready
			d.agent.HandlerContainerSyncCheck(context.Background(), d.clusterKey, d.hostName)
			d.agent.MqReady(true)
			d.mqReady.Store(true)

			d.listAll()
			d.agent.HandlerContainerSync(context.Background(), d.clusterKey, d.hostName, t)
			d.synced.Store(true)
		}
		// handle docker events
		d.ListenEvents(d.saveContainerData)
	}()

	return nil
}

func (d *DockerInfoManager) saveContainerData(containerID string, timestamp int64) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	if len(containerID) == 0 || timestamp <= 0 {
		return
	}

	containerID = strings.TrimPrefix(containerID, "docker://")
	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}
	d.Lock()
	defer d.Unlock()
	d.containerData[containerID] = timestamp
}

func (d *DockerInfoManager) FindContainerCacheData(containerID string) (int64, bool) {
	if len(containerID) == 0 {
		return 0, false
	}
	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}
	d.RLock()
	defer d.RUnlock()
	timestamp, ok := d.containerData[containerID]
	return timestamp, ok
}

// buildContainerDetail get container detail infos by ContainerInspect, and for kubernetes
// pause container, it returns nil container
func (d *DockerInfoManager) buildContainerDetail(containerID string) (*model.TensorRawContainer, error) {
	containerJson, err := d.dockerCli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		logging.Get().Err(err).Msgf("get container info: %s err", containerID)
		return nil, err
	}
	// exclude pause container in kubernetes pod
	if containerJson.Config.Labels["io.kubernetes.docker.type"] == "podsandbox" {
		return nil, nil
	}
	container := d.containerFromRaw(&containerJson)
	return container, nil
}

// processEvents  process container events
func (d *DockerInfoManager) processEvents(ctx context.Context, container *model.TensorRawContainer, action string) {
	if container.K8sManaged && container.ResourceName == "" && !isDeleteEvent(action) {
		func() {
			logging.Get().Debug().Str("raw-container", "process event").Msgf("get pod owner of %s/%s/%s",
				container.Namespace, container.PodName, container.Name)
			resName, resKind, err := d.store.GetPodOwner(container.Namespace, container.PodName)
			if err != nil {
				logging.Get().Warn().Err(err).Msg("get pod owner err")
				return
			}
			container.ResourceName = resName
			container.ResourceKind = resKind
			pod, err := d.store.GetPod(container.Namespace, container.PodName)
			if err != nil {
				logging.Get().Warn().Err(err).Msgf("get pod:%s/%s err", container.Namespace, container.Name)
				return
			}

			var volumeMounts []model.Mounts
			var ports []model.Port
			/*list containers*/
			for _, c := range pod.Spec.Containers {
				for _, m := range c.VolumeMounts {
					volumeMounts = append(volumeMounts, model.Mounts{
						MountPath:   m.MountPath,
						SubPath:     m.SubPath,
						SubPathExpr: m.SubPathExpr,
					})
				}

				for _, p := range c.Ports {
					ports = append(ports, model.Port{Name: p.Name, ContainerPort: p.ContainerPort})
				}

			}
			container.IP = pod.Status.PodIP
			container.Ports = utils.MergeContainerPorts(ports, container.Ports, pod.Status.PodIP)
			container.VolumeMounts = utils.MergeVolumeMounts(volumeMounts, container.VolumeMounts)
			//	找回 image tag：   pod自定义标签 在容器运行时中没有
			container.ImageName = buildImageWithTag(container.ImageName, pod.Labels, container.Name)
			container.ImageUUID = model.GetImageUUID(container.ImageName, container.ImageDigest)
		}()
	}
	logging.Get().Debug().Msgf("raw-container - process container [%s:%s:%d] event: %s",
		container.ContainerID, container.Name, container.Status, action)
	switch action {
	case "create", "start":
		for _, handler := range d.handlers {
			handler.OnAdd(container)
		}
	case "restart", "rename", "resize":
		for _, handler := range d.handlers {
			handler.OnUpdate(nil, container)
		}
	case "stop", "destroy":
		for _, handler := range d.handlers {
			logging.Get().Debug().Msgf("raw-container - event: delete container %s", container.ContainerID)
			handler.OnDelete(container)
		}
	default:
		logging.Get().Info().Msgf("received unknown event: %s", action)
	}
}

// listAll list all container from runtime
func (d *DockerInfoManager) listAll() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	containers, err := d.dockerCli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		logging.Get().Err(err).Msg("failed to list containers")
		return
	}
	for _, c := range containers {
		logging.Get().Debug().Str("raw-container", "list all containers").Msgf("%s/%v", c.ID, c.Names)
		containerDetail, err := d.buildContainerDetail(c.ID)
		if err != nil {
			return
		}
		if containerDetail == nil {
			continue
		}
		d.processEvents(ctx, containerDetail, "create")
	}
}

func (d *DockerInfoManager) containerFromRaw(containerJson *types.ContainerJSON) *model.TensorRawContainer {
	volumeMounts := make([]model.Mounts, 0, len(containerJson.Mounts))
	var isNfs, isCephfs, isHostPath bool
	for _, m := range containerJson.Mounts {
		ro := false
		if m.Mode == "ro" {
			ro = true
		}
		volumeMounts = append(volumeMounts, model.Mounts{
			Type:             string(m.Type),
			Name:             m.Name,
			ReadOnly:         ro,
			SourcePath:       m.Source,
			MountPath:        m.Destination,
			MountPropagation: string(m.Propagation),
		})
		if strings.Contains(m.Source, StorageTypeNfs) {
			isNfs = true
		} else if strings.Contains(m.Source, StorageTypeCephfs) {
			isCephfs = true
		} else {
			isHostPath = true
		}
	}
	var k8sManaged bool
	podName, ok := containerJson.Config.Labels["io.kubernetes.pod.name"]
	if ok {
		k8sManaged = true
	}
	podUid := containerJson.Config.Labels["io.kubernetes.pod.uid"]

	createdAt, _ := time.Parse(time.RFC3339Nano, containerJson.Created)
	finishedAt, _ := time.Parse(time.RFC3339Nano, containerJson.State.FinishedAt)
	containerFullName := strings.TrimPrefix(containerJson.Name, "/")
	containerName := containerJson.Config.Labels["io.kubernetes.container.name"]
	if containerName == "" {
		containerName = containerFullName
	}
	if containerName == "" {
		containerName = stringid.TruncateID(containerJson.ID)
	}
	processes := getContainerProcessInfo(containerJson.State.Pid)
	imageName, imageDigest, imageCreated, imageSize := d.getImageInfoV2(containerJson.Config.Image, containerJson.Image)
	var user string
	if containerJson.Config.User == "0" {
		user = "root"
	} else {
		var uid string
		split := strings.Split(containerJson.Config.User, ":")
		if len(split) == 2 {
			uid = split[0]
		} else if _, err := strconv.ParseInt(containerJson.Config.User, 10, 32); err == nil {
			uid = containerJson.Config.User
		}
		if uid != "" {
			ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
			resp, err := d.RunCmd(ctx, containerJson.ID, []string{"/bin/sh", "-c", "whoami"})
			if err == nil && resp != "" && !strings.Contains(resp, "stdout:") && !strings.Contains(resp, "OCI runtime exec failed") {
				user = strings.TrimSpace(resp)
			}
		}
		if user == "" {
			user = containerJson.Config.User
		}
	}

	return &model.TensorRawContainer{
		Status:         getContainerStatus(containerJson.State.Status),
		CreatedAt:      createdAt,
		UpdatedAt:      time.Now(),
		LastStopTime:   finishedAt,
		ContainerID:    containerJson.ID,
		IP:             containerJson.NetworkSettings.IPAddress,
		IPV6:           containerJson.NetworkSettings.GlobalIPv6Address,
		Gateway:        containerJson.NetworkSettings.Gateway,
		Mac:            containerJson.NetworkSettings.MacAddress,
		NetworkMode:    getNetworkMode(string(containerJson.HostConfig.NetworkMode)),
		Name:           containerName,
		FullName:       containerFullName,
		Labels:         containerJson.Config.Labels,
		PodName:        podName,
		PodUid:         podUid,
		Namespace:      containerJson.Config.Labels["io.kubernetes.pod.namespace"],
		ClusterKey:     d.clusterKey,
		NodeName:       d.hostName,
		NodeIP:         d.hostIP,
		ImageName:      imageName,
		ImageCreated:   imageCreated,
		ImageSize:      imageSize,
		ImageID:        containerJson.Image,
		ImageDigest:    imageDigest,
		Cmd:            getCommandFromDocker(containerJson),
		Arguments:      containerJson.Args,
		VolumeMounts:   volumeMounts,
		StorageType:    getContainerStorageType(isNfs, isCephfs, isHostPath),
		Path:           containerJson.Path,
		ReservedCPU:    getCPUFromDocker(containerJson),
		ReservedMemory: containerJson.HostConfig.Memory,
		Pid:            containerJson.State.Pid,
		K8sManaged:     k8sManaged,
		Environment:    util.DeIdentificationEnvs(containerJson.Config.Env),
		ProcessNumber:  len(processes),
		Processes:      processes,
		User:           user,
		Ports:          getContainerPorts(containerJson.State.Pid),
	}
}

func (d *DockerInfoManager) containerFromEvent(message events.Message) *model.TensorRawContainer {
	var k8sManaged bool
	podName, ok := message.Actor.Attributes["io.kubernetes.pod.name"]
	if ok {
		k8sManaged = true
	}
	podUid := message.Actor.Attributes["io.kubernetes.pod.uid"]

	containerName := message.Actor.Attributes["io.kubernetes.container.name"]
	if containerName == "" {
		containerName = strings.TrimPrefix(message.Actor.Attributes["name"], "/")
	}
	if containerName == "" {
		containerName = stringid.TruncateID(message.ID)
	}
	return &model.TensorRawContainer{
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Unix(message.Time, 0),
		Status:      getContainerStatus(message.Status),
		ContainerID: message.ID,
		FullName:    strings.TrimPrefix(message.Actor.Attributes["name"], "/"),
		Name:        containerName,
		PodName:     podName,
		PodUid:      podUid,
		Namespace:   message.Actor.Attributes["io.kubernetes.pod.namespace"],
		ClusterKey:  d.clusterKey,
		NodeName:    d.hostName,
		NodeIP:      d.hostIP,
		K8sManaged:  k8sManaged,
	}
}

func (d *DockerInfoManager) updateContainerDetail(ctx context.Context, container *model.TensorRawContainer) *model.TensorRawContainer {
	containerJson, err := d.dockerCli.ContainerInspect(ctx, container.ContainerID)
	if err != nil {
		logging.Get().Err(err).Str("raw-container", "update container").Msgf("get container info: %s err", container.ContainerID)
		return container
	}
	volumeMounts := make([]model.Mounts, 0, len(containerJson.Mounts))
	var isNfs, isCephfs, isHostPath bool
	for _, m := range containerJson.Mounts {
		ro := false
		if m.Mode == "ro" {
			ro = true
		}
		volumeMounts = append(volumeMounts, model.Mounts{
			Type:             string(m.Type),
			Name:             m.Name,
			ReadOnly:         ro,
			SourcePath:       m.Source,
			MountPath:        m.Destination,
			MountPropagation: string(m.Propagation),
		})
		if strings.Contains(m.Source, StorageTypeNfs) {
			isNfs = true
		} else if strings.Contains(m.Source, StorageTypeCephfs) {
			isCephfs = true
		} else {
			isHostPath = true
		}
	}

	t, err := time.Parse(time.RFC3339Nano, containerJson.Created)
	if err != nil {
		return container
	}
	container.CreatedAt = t
	container.Status = getContainerStatus(containerJson.State.Status)
	container.Cmd = getCommandFromDocker(&containerJson)
	container.Arguments = containerJson.Args
	container.Path = containerJson.Path
	container.ReservedCPU = getCPUFromDocker(&containerJson)
	container.ReservedMemory = containerJson.HostConfig.Memory
	container.Pid = containerJson.State.Pid
	container.IP = containerJson.NetworkSettings.IPAddress
	container.IPV6 = containerJson.NetworkSettings.GlobalIPv6Address
	container.Gateway = containerJson.NetworkSettings.Gateway
	container.Mac = containerJson.NetworkSettings.MacAddress
	container.Labels = containerJson.Config.Labels
	container.NetworkMode = getNetworkMode(string(containerJson.HostConfig.NetworkMode))
	container.VolumeMounts = volumeMounts
	container.StorageType = getContainerStorageType(isNfs, isCephfs, isHostPath)
	container.Environment = util.DeIdentificationEnvs(containerJson.Config.Env)
	container.ImageID = containerJson.Image
	container.ImageName, container.ImageDigest, container.ImageCreated, container.ImageSize = d.getImageInfoV2(containerJson.Config.Image, container.ImageID)
	var user string
	if containerJson.Config.User == "0" {
		user = "root"
	} else {
		var uid string
		split := strings.Split(containerJson.Config.User, ":")
		if len(split) == 2 {
			uid = split[0]
		} else if _, err := strconv.ParseInt(containerJson.Config.User, 10, 32); err == nil {
			uid = containerJson.Config.User
		}
		if uid != "" {
			ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
			resp, err := d.RunCmd(ctx, containerJson.ID, []string{"/bin/sh", "-c", "whoami"})
			if err == nil && resp != "" && !strings.Contains(resp, "stdout:") {
				user = strings.TrimSpace(resp)
			}
		}
		if user == "" {
			user = containerJson.Config.User
		}
	}
	container.User = user
	container.Ports = getContainerPorts(container.Pid)

	processes := getContainerProcessInfo(container.Pid)
	container.ProcessNumber = len(processes)
	container.Processes = processes
	return container
}

func (d *DockerInfoManager) getImageNames(imageID string) string {
	// containerJson.Config.Image:
	// harbor.tensorsecurity.com/tensorsecurity/sac-frontend@sha256:6c5eea27bd5e1da0b5a5cb7ccc0fa850cdd0e3277cfea0c5026fd7e4bee2b623
	imageInspect, _, err := d.dockerCli.ImageInspectWithRaw(context.Background(), imageID)
	if err != nil {
		logging.Get().Err(err).Str("raw-container", "get image name").Msgf("failed to get image [%s] info: %w ", imageID, err)
	}
	var names string
	for i, rt := range imageInspect.RepoTags {
		if i == 0 {
			names = rt
		} else {
			names = fmt.Sprintf("%s, %s", names, rt)
		}
	}
	return names
}
func (d *DockerInfoManager) getImageInfo(imageID string) (string, string, int64) {
	// containerJson.Config.Image:
	// harbor.tensorsecurity.com/tensorsecurity/sac-frontend@sha256:6c5eea27bd5e1da0b5a5cb7ccc0fa850cdd0e3277cfea0c5026fd7e4bee2b623
	imageInspect, _, err := d.dockerCli.ImageInspectWithRaw(context.Background(), imageID)
	if err != nil {
		logging.Get().Err(err).Str("raw-container", "get image name").Msgf("failed to get image [%s] info: %w ", imageID, err)
	}
	var names string
	for i, rt := range imageInspect.RepoTags {
		if i == 0 {
			names = rt
		} else {
			names = fmt.Sprintf("%s, %s", names, rt)
		}
	}
	return names, imageInspect.Created, imageInspect.Size
}

/*
imageRef:

		1:docker.io/library/nginx:latest
	   2： library/nginx:latest
	   3:  nginx:latest
	   4： nginx
	   5: sha256:：xxxx
	   6：docker.io/library/nginx@sha256xxxx
	   7：library/nginx@sha256xxxx
	   8：nginx@sha256xxxx
*/
func (d *DockerInfoManager) getImageInfoV2(imageRef string, imageID string) (imageName string, imageDigest string, createTime string, size int64) {
	imageInspect, _, err := d.dockerCli.ImageInspectWithRaw(context.Background(), imageID)
	if err != nil {
		logging.Get().Err(err).Str("raw-container", "get image name").Msgf("failed to get image [%s] info: %w ", imageID, err)
	}
	defer func() {
		logging.Get().Debug().Msgf("getImageInfoV2: imageRef:%s, return imageName:%s", imageRef, imageName)
	}()

	i := strings.LastIndex(imageRef, "@") // 镜像仓库修改过tag  name@sha256:xxxx
	if i != -1 && i < len(imageRef)-1 {
		imageDigest = imageRef[i+1:]
		if len(imageInspect.RepoTags) > 0 {
			imageName = imageInspect.RepoTags[0]
		}
	} else if strings.HasPrefix(imageRef, "sha256") && len(imageInspect.RepoTags) > 0 {
		//sha256:xxx
		imageName = imageInspect.RepoTags[0]
		imageDigest = imageRef
	}
	if imageName == "" {
		imageName = imageRef
	}

	// name
	count := strings.Count(imageName, "/")
	switch count {
	case 0: //  tomcat
		imageName = "library/" + imageName
	case 1, 2: // library/tomcat:latest
	default:
		imageName = strings.TrimPrefix(imageName, "http://")
		imageName = strings.TrimPrefix(imageName, "https://")
	}

	if imageDigest == "" && len(imageInspect.RepoDigests) > 0 {
		i := strings.LastIndex(imageInspect.RepoDigests[0], "@")
		if i != -1 && i < len(imageInspect.RepoDigests[0])-1 {
			imageDigest = imageInspect.RepoDigests[0][i+1:]
		}
	}

	if !strings.Contains(imageName, ":") && len(imageInspect.RepoTags) > 0 {
		split := strings.Split(imageInspect.RepoTags[0], ":")
		imageName += ":" + split[len(split)-1]
	}

	return imageName, imageDigest, imageInspect.Created, imageInspect.Size
}

func (d *DockerInfoManager) RunCmd(ctx context.Context, containerId string, cmd []string) (resp string, err error) {
	cmdStr := fmt.Sprint(cmd)

	if containerId == "" || len(cmd) == 0 {
		return "", errors.New("param is empty.  containerId:" + containerId + " cmd:" + cmdStr)
	}

	tCtx, cancelFunc := context.WithTimeout(ctx, 5*time.Second)
	defer cancelFunc()

	logging.Get().Debug().Msgf("RunCmd run cmd:[%s] in container:[%s]", cmd, containerId)
	execConfig := types.ExecConfig{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
	}
	createData, err := d.dockerCli.ContainerExecCreate(tCtx, containerId, execConfig)
	if err != nil {
		logging.Get().Debug().Msgf("RunCmd  ContainerExecCreate failed.%w", err)
		return "", err
	}
	attachData, err := d.dockerCli.ContainerExecAttach(tCtx, createData.ID, types.ExecStartCheck{})
	if err != nil {
		logging.Get().Debug().Msgf("RunCmd  ContainerExecAttach failed.%w", err)
		return "", err
	}
	defer attachData.Close()

	stdOut := bytes.Buffer{}
	stdErr := bytes.Buffer{}
	_, err = stdcopy.StdCopy(&stdOut, &stdErr, attachData.Reader)
	if err != nil {
		logging.Get().Debug().Msgf("RunCmd  Read output  failed.%w", err)
		return "", err
	}
	if stdErr.Len() == 0 {
		return strings.TrimSpace(string(stdOut.Bytes())), nil
	}
	return fmt.Sprintf("stdout:%sstderr:%s", string(stdOut.Bytes()), string(stdErr.Bytes())), nil
}

func (d *DockerInfoManager) addRetryContainer(containerId string) {
	if containerId == "" {
		return
	}
	logging.Get().Debug().Msgf("addRetryContainer: containerId:%s", containerId)
	d.retryMapLock.Lock()
	d.retryMap[containerId] = &dockerRetryItem{
		containerId: containerId,
		outTime:     time.Now().Add(time.Minute),
	}
	d.retryMapLock.Unlock()
}

func (d *DockerInfoManager) Retry() {
	timer := time.NewTicker(time.Minute)
	for range timer.C {
		//logging.Get().Debug().Msg("retry begin")
		var itemList []*dockerRetryItem
		now := time.Now()
		d.retryMapLock.Lock()
		for key, value := range d.retryMap {
			if value.outTime.Before(now) {
				itemList = append(itemList, value)
				delete(d.retryMap, key)
			}
		}
		d.retryMapLock.Unlock()
		for _, item := range itemList {
			d.retryOnce(context.Background(), item.containerId)
		}
	}
}

func (d *DockerInfoManager) retryOnce(ctx context.Context, containerId string) {
	containerDetail, err := d.buildContainerDetail(containerId)
	if err != nil {
		logging.Get().Err(err).Msgf("retry failed. containerId:%s", containerId)
		return
	}
	if containerDetail == nil {
		logging.Get().Debug().Msgf("retry: ignore nil  container")
		return
	}
	logging.Get().Debug().Msgf("retry finish, containerId:%s", containerId)
	d.processEvents(ctx, containerDetail, "create")
}

func getImageDigest(image string) string {
	i := strings.LastIndex(image, "@")
	if i != -1 && i < len(image)-1 {
		return image[i+1:]
	}
	return image
}
func getContainerStatus(st string) int32 {
	status := assets.Exited
	switch st {
	case "exited":
		status = assets.Exited
	case "running":
		status = assets.Running
	case "paused":
		status = assets.Paused
	case "created":
		status = assets.Created
	case "restarting":
		status = assets.Restarting
	case "removing":
		status = assets.Removing
	case "dead":
		status = assets.Dead
	}
	return int32(status)
}

func getCPUFromDocker(json *types.ContainerJSON) int64 {
	if json.HostConfig.NanoCPUs > 0 {
		return json.HostConfig.NanoCPUs / 1000000
	} else {
		if json.HostConfig.CPUPeriod > 0 {
			return json.HostConfig.CPUQuota * 1000 / json.HostConfig.CPUPeriod
		}
	}
	return 0
}

func getCommandFromDocker(json *types.ContainerJSON) []string {
	if len(json.Config.Cmd) > 0 {
		return json.Config.Cmd
	} else if len(json.Config.Entrypoint) > 0 {
		return json.Config.Entrypoint
	}
	return nil
}

func getContainerProcessInfo(pid int) []model.ProcessData {
	processInfo, err := GetContainerProcessInfo(pid, "/host")
	logging.Get().Debug().Msgf("raw-container - pid: %d, %+v", pid, processInfo)
	if err != nil {
		logging.Get().Err(err).Str("raw-container", "get container process").Msg("failed to get container processes")
		return nil
	}
	processes := make([]model.ProcessData, 0, len(processInfo))
	for _, p := range processInfo {
		processes = append(processes, model.ProcessData{
			HostPid:      p.HostPid,
			ContainerPid: p.ContainerPid,
			Comm:         p.Comm,
			UserName:     p.UserName,
			StartTime:    p.StartTime,
		})
	}
	return processes
}
func getContainerPorts(pid int) []model.Port {
	dockerPorts, err := GetListenPort(pid, "/host")
	if err != nil {
		return nil
	}
	logging.Get().Debug().Str("raw-container", "get container ports").Msgf("container pid: %d, ports number: %d", pid, len(dockerPorts))
	ports := make([]model.Port, 0, len(dockerPorts))
	for _, p := range dockerPorts {
		ports = append(ports, model.Port{
			Name:          "",
			ContainerPort: int32(p.Port),
			Proto:         p.Proto,
			HostIP:        p.HostIp,
		})
	}
	return ports
}

func isDeleteEvent(action string) bool {
	if action == "stop" || action == "destroy" {
		return true
	}
	return false
}

func getNetworkMode(mode string) string {
	if mode == "default" {
		return "bridge"
	} else if strings.HasPrefix(mode, "container:") {
		return "container"
	}
	return mode
}

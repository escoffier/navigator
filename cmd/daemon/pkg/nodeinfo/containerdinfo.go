package nodeinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/services/tasks/v1"
	taskPkg "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/events/exchange"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/protobuf"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/typeurl/v2"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/docker/go-connections/nat"
	"github.com/google/cadvisor/container/containerd/namespaces"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo/native"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/utils"
	assetsPkg "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	cri "k8s.io/cri-api/pkg/apis"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const containerK8sNamespace = "k8s.io"
const shortContainerIDLength int = 12
const clientConnectTimeout time.Duration = time.Duration(5 * time.Second)

const (
	StorageTypeNfs    = "kubernetes.io~nfs"
	StorageTypeCephfs = "kubernetes.io~rbd"
)

type ContainerdInfoManager struct {
	containerdCli *containerd.Client
	hostIP        string
	hostName      string
	containerData map[string]int64 // map[containerId]time
	handlers      []ContainerEventHandler
	agent         *containerassets.Agent
	store         containerassets.PodCache
	clusterKey    string
	mqReady       atomic.Bool
	sync.RWMutex
	runClient    cri.RuntimeService // 向容器发送命令
	retryMap     map[string]*containerdRetryItem
	retryMapLock *sync.Mutex
	synced       atomic.Bool
}

type containerdRetryItem struct {
	namespace   string
	containerId string
	outTime     time.Time
}

// unix://xxx
func GetContainerdAddr() string {
	uri := os.Getenv("CONTAINERD_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/containerd/containerd.sock"
	}
	return uri
}

func NewContainerdInfoManager(clusterKey, hostName, hostIP string, agent *containerassets.Agent) (*ContainerdInfoManager, error) {
	uri := GetContainerdAddr()
	containerdCli, err := containerd.New(strings.TrimPrefix(uri, "unix://"), containerd.WithTimeout(clientConnectTimeout))
	if err != nil {
		return nil, errors.Errorf("containerd new client failed, %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), clientConnectTimeout)
	defer cancel()

	_, err = containerdCli.IsServing(ctx)
	if err != nil {
		return nil, errors.Errorf("check containerd daemon is serving failed,%v", err)
	}
	version, err := containerdCli.Version(ctx)
	if err != nil {
		return nil, errors.Errorf("get containerd version failed,%v", err)
	}
	logging.Get().Info().Str("CRI", ContainerdType).Msgf("containerd version: %v", version)

	containerdInfoManager := ContainerdInfoManager{
		containerdCli: containerdCli,
		hostIP:        hostIP,
		hostName:      hostName,
		containerData: make(map[string]int64, 30),
		agent:         agent,
		clusterKey:    clusterKey,
		retryMap:      make(map[string]*containerdRetryItem),
		retryMapLock:  new(sync.Mutex),
	}
	containerdInfoManager.mqReady.Store(false)
	go func() {
		defer func() {
			r := recover()
			if r != nil {
				logging.Get().Error().Str("CRI", ContainerdType).Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		containerdInfoManager.clearContainerTimeoutData()
	}()
	go func() {
		defer func() {
			r := recover()
			if r != nil {
				logging.Get().Error().Str("CRI", ContainerdType).Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		containerdInfoManager.Retry()
	}()
	runClient, err := remote.NewRemoteRuntimeService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("containerd new NewContainerdInfoManager failed, %v", err)
	}
	containerdInfoManager.runClient = runClient
	return &containerdInfoManager, nil
}

func (d *ContainerdInfoManager) Synced() bool {
	return d.synced.Load()
}

func (d *ContainerdInfoManager) clearContainerTimeoutData() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	count := 0
	for now := range ticker.C {
		func(nowTime time.Time) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Str("CRI", ContainerdType).Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()

			d.Lock()
			defer d.Unlock()
			d.retryMapLock.Lock()
			defer d.retryMapLock.Unlock()

			if count >= 60 { // if a map keeps a stable size but is with continuous add or delete, it should be reconstructed after a period of time to prevent memory leak
				newMap := make(map[string]int64, len(d.containerData))
				for containerID, timestamp := range d.containerData {
					if nowTime.Unix()-timestamp >= containerIDTimeoutSec {
						continue
					}
					newMap[containerID] = timestamp
				}
				d.containerData = newMap

				newRetryMap := make(map[string]*containerdRetryItem, len(d.retryMap))
				for containerID, timestamp := range d.retryMap {
					newRetryMap[containerID] = timestamp
				}
				d.retryMap = newRetryMap

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

func (d *ContainerdInfoManager) GetContainerPid(containerID string) (int, string, error) {
	if containerID == "" {
		return 0, "", fmt.Errorf("container ID is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	nsCtx := namespaces.WithNamespace(ctx, containerK8sNamespace)
	id := strings.TrimPrefix(containerID, "containerd://")
	response, err := d.containerdCli.TaskService().Get(nsCtx, &tasks.GetRequest{
		ContainerID: id,
	})
	if err != nil {
		return 0, "", err
	}
	logging.Get().Debug().Msgf("containerd GetContainerPid pid:%d, id:%s, err:%v", response.Process.Pid, id, err)
	return int(response.Process.Pid), id, nil

}

func (d *ContainerdInfoManager) ListenEvents(saveData SaveContainerDataFunc) {
	newExchange := exchange.NewExchange()
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	filters := []string{
		fmt.Sprintf(`topic=="%s"`, runtime.TaskStartEventTopic),
		fmt.Sprintf(`topic=="%s"`, runtime.TaskPausedEventTopic),
		fmt.Sprintf(`topic=="%s"`, runtime.TaskResumedEventTopic),
		fmt.Sprintf(`topic=="%s"`, runtime.TaskDeleteEventTopic),
		fmt.Sprintf(`topic=="%s"`, runtime.TaskExitEventTopic),
	}

	msg, errs := d.containerdCli.Subscribe(ctx, filters...)
	for {
		select {
		case m := <-msg:
			go func() {
				currentCtx, cancel := context.WithTimeout(ctx, time.Second*5)
				defer cancel()
				v, err := typeurl.UnmarshalAny(m.Event)
				if err != nil {
					logging.Get().Err(err).Any("event", m).Msg("failed to unmarshal event")
					return
				}
				var (
					containerId string
					pid         uint32
				)
				action := ""
				switch t := v.(type) {
				case *events.TaskStart:
					containerId = t.ContainerID
					pid = t.Pid
					action = "start"
					time.Sleep(time.Second) //todo
				case *events.TaskDelete:
					containerId = t.ContainerID
					pid = t.Pid
					action = "delete"
				case *events.TaskExit:
					containerId = t.ContainerID
					pid = t.Pid
					action = "exit"
				case *events.TaskPaused:
					containerId = t.ContainerID
					action = "pause"
				case *events.TaskResumed:
					containerId = t.ContainerID
					action = "resume"
				default:
					logging.Get().Error().Msgf("containerd ignore event, namespace:%s,topic:%s,event:%s", m.Namespace, m.Topic, m.Event.GetTypeUrl())
					return
				}
				logging.Get().Info().Msgf("containerd received event ,topic:%s,namespace:%s,containerId:%s", m.Topic, m.Namespace, containerId)
				saveData(containerId, m.Timestamp.Unix())

				if d.mqReady.Load() {
					nsCtx := namespaces.WithNamespace(currentCtx, m.Namespace)
					if ExportRawContainer {
						contain := &model.TensorRawContainer{Namespace: m.Namespace, ContainerID: containerId, ClusterKey: d.clusterKey, Pid: int(pid)}
						if m.Topic == runtime.TaskStartEventTopic {
							c, err := d.containerdCli.LoadContainer(nsCtx, containerId)
							if err != nil {
								logging.Get().Error().Msgf("get container in containerd failed .%v", err)
								return
							}
							task, err := d.containerdCli.TaskService().Get(nsCtx, &tasks.GetRequest{
								ContainerID: c.ID(),
							})
							if err != nil {
								logging.Get().Error().Msgf("get task by container  failed. %v", err)
								return
							}
							contain, err = d.buildContainerDetail(nsCtx, c, task.Process)
							if err != nil {
								logging.Get().Info().Msgf("ignore container, err:%v ", err)
								return
							}
							if contain == nil {
								return
							}
							//	 If the container port is empty, try again after 1 minute
							if len(contain.Ports) == 0 {
								d.addRetryContainer(m.Namespace, contain.ContainerID)
							}
						} else if m.Topic == runtime.TaskExitEventTopic || m.Topic == runtime.TaskDeleteEventTopic {
							contain.LastStopTime = m.Timestamp
							contain.StatusDesc = taskPkg.Status_name[int32(taskPkg.Status_STOPPED)]
						} else {
							contain.LastStopTime = m.Timestamp
							contain.Status, contain.StatusDesc = d.getContainerStatus(nsCtx, containerId)
						}
						d.processEvents(contain, action)
					}
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

func (d *ContainerdInfoManager) saveContainerData(containerID string, timestamp int64) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	if len(containerID) == 0 || timestamp <= 0 {
		return
	}

	if len(containerID) > shortContainerIDLength {
		containerID = containerID[0:shortContainerIDLength]
	}
	d.Lock()
	defer d.Unlock()
	d.containerData[containerID] = timestamp
}

func (d *ContainerdInfoManager) FindContainerCacheData(containerID string) (int64, bool) {
	if len(containerID) == 0 {
		return 0, false
	}
	if len(containerID) > shortContainerIDLength {
		containerID = containerID[0:shortContainerIDLength]
	}
	d.RLock()
	defer d.RUnlock()
	timestamp, ok := d.containerData[containerID]
	return timestamp, ok
}

func (d *ContainerdInfoManager) Start() error {
	t := time.Now()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		logging.Get().Warn().Msg("start ContainerdInfoManager")
		if ExportRawContainer {
			// check if mq ready
			d.agent.HandlerContainerSyncCheck(context.Background(), d.clusterKey, d.hostName)
			d.agent.MqReady(true)
			d.mqReady.Store(true)

			d.listAll()
			d.agent.HandlerContainerSync(context.Background(), d.clusterKey, d.hostName, t)
			d.synced.Store(true)
		}
		// handle containerd events
		d.ListenEvents(d.saveContainerData)
	}()
	return nil
}

func (d *ContainerdInfoManager) AddEventHandler(handler ContainerEventHandler) {
	d.handlers = append(d.handlers, handler)
}

func (d *ContainerdInfoManager) SetPodStore(store containerassets.PodCache) {
	d.store = store
}

func (d *ContainerdInfoManager) listAll() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	namespaceList, err := d.containerdCli.NamespaceService().List(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("cri: get namespace failed .")
		return
	}
	logging.Get().Info().Msgf("namespace List :%v", namespaceList)
	for _, namespace := range namespaceList {
		nsCtx := namespaces.WithNamespace(ctx, namespace)
		tasksResponse, err := d.containerdCli.TaskService().List(nsCtx, &tasks.ListTasksRequest{})
		if err != nil {
			logging.Get().Err(err).Msg("get taskList failed .")
		}
		for _, task := range tasksResponse.Tasks {
			if task.ContainerID == "" {
				task.ContainerID = task.ID
			}
			container, err := d.containerdCli.LoadContainer(nsCtx, task.ContainerID)
			if err != nil {
				logging.Get().Err(err).Msg("get container failed .")
				continue
			}
			containerDetail, err := d.buildContainerDetail(nsCtx, container, task)
			if err != nil {
				logging.Get().Info().Msgf("ignore container:  err:%v ", err)
				continue
			}
			if containerDetail == nil {
				continue
			}
			d.processEvents(containerDetail, "start")
		}
	}
}

func (d *ContainerdInfoManager) buildContainerDetail(ctx context.Context, c containerd.Container, t *taskPkg.Process) (*model.TensorRawContainer, error) {
	labels, err := c.Labels(ctx)
	if err != nil {
		logging.Get().Err(err).Msgf("get container labels failed.")
		return nil, err
	}
	// exclude pause container in kubernetes pod
	if labels != nil && labels["io.cri-containerd.kind"] == "sandbox" {
		logging.Get().Info().Msgf("skip sandbox container,containerId:%s", c.ID())
		return nil, nil
	}

	tensorContainer, err := d.containerFromRaw(ctx, c, t)
	if err != nil {
		return nil, err
	}
	return tensorContainer, nil
}

func getMountPropagationAndIsRO(fstab []string) (string, bool) {
	if len(fstab) == 0 {
		return "", false
	}
	var mountPropagetion string
	var ro bool
	for _, str := range fstab {
		switch str {
		case "ro":
			ro = true
		case "rshared", "rprivate", "rslave":
			mountPropagetion = str
		}
	}
	return mountPropagetion, ro
}

func (d *ContainerdInfoManager) containerFromRaw(ctx context.Context, container containerd.Container, t *taskPkg.Process) (*model.TensorRawContainer, error) {
	info, err := container.Info(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("get container info err in containerd")
		return nil, err
	}
	if info.Image == "" {
		logging.Get().Err(err).Msg("ignore container, without image. containerId:" + container.ID())
		return nil, err
	}
	spec, err := container.Spec(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("get container spec err in containerd")
		return nil, err
	}
	volumeMounts := make([]model.Mounts, 0, len(spec.Mounts))
	var isNfs, isCephfs, isHostPath bool
	for _, m := range spec.Mounts {
		mountPropagation, ro := getMountPropagationAndIsRO(m.Options)
		volumeMounts = append(volumeMounts, model.Mounts{
			Type:             m.Type,
			ReadOnly:         ro,
			SourcePath:       m.Source,
			MountPath:        m.Destination,
			MountPropagation: mountPropagation,
		})
		if strings.Contains(m.Source, StorageTypeNfs) {
			isNfs = true
		} else if strings.Contains(m.Source, StorageTypeCephfs) {
			isCephfs = true
		} else {
			isHostPath = true
		}
	}
	var pid int
	var networkModel string
	namespace, ok := namespaces.Namespace(ctx)
	if ok && namespace == containerK8sNamespace {
		networkModel = "container"
	}
	if pid == 0 {
		pid = int(t.Pid)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		logging.Get().Warn().Str("containerId", container.ID()).Msgf("get container's Task failed, err:%v", err)
		return nil, err
	}
	processes, err := task.Pids(ctx)
	if err != nil {
		logging.Get().Warn().Str("taskId", task.ID()).Msgf("get processes failed,err:%v", err)
	}
	var k8sManaged bool
	podName, ok := info.Labels["io.kubernetes.pod.name"]
	if ok {
		k8sManaged = true
	}
	containerName := info.Labels["io.kubernetes.container.name"]
	var (
		imageId      = info.Image
		imageName    = info.Image
		imageCreated string
		imageSize    int64
		imageDigest  string
	)
	image, err := container.Image(ctx)
	if err != nil {
		logging.Get().Error().Str("contaienrId", container.ID()).Msgf("get image failed,err:%v,info.Image:%s", err, info.Image)
		//return nil, errors.New(fmt.Sprintf("containerId:%s get image failed,err:%v", container.ID(), err))
	} else {
		imageId = image.Name()
		imageName = image.Name()
		imageCreated = image.Metadata().CreatedAt.Format(time.RFC3339Nano)
		imageDigest = image.Target().Digest.String()
		imageSize, err = image.Size(ctx)
		if err != nil {
			logging.Get().Error().Msgf("get image size  failed,err:%v ", err)
		}
	}
	networkSettings, err := d.TryGetNetworkSettings(pid)
	if err != nil {
		logging.Get().Error().Msg("TryGetNetworkSettings failed,err:" + err.Error())
		networkSettings = &NetworkSettings{}
	}
	tensorRawContainer := &model.TensorRawContainer{
		Status:         d.getCRIStatusFromContainerdStatus(t.Status),
		StatusDesc:     taskPkg.Status_name[int32(t.Status)],
		CreatedAt:      info.CreatedAt.UTC(),
		LastStopTime:   protobuf.FromTimestamp(t.ExitedAt).UTC(),
		UpdatedAt:      time.Now(),
		ContainerID:    container.ID(),
		IP:             networkSettings.IPAddress,
		IPV6:           networkSettings.GlobalIPv6Address,
		Mac:            networkSettings.MacAddress,
		NetworkMode:    networkModel,
		Name:           containerName,
		FullName:       containerName,
		PodName:        podName,
		PodUid:         info.Labels["io.kubernetes.pod.uid"],
		Namespace:      info.Labels["io.kubernetes.pod.namespace"],
		ClusterKey:     d.clusterKey,
		NodeName:       d.hostName,
		NodeIP:         d.hostIP,
		Labels:         info.Labels,
		ImageName:      imageName,
		ImageCreated:   imageCreated,
		ImageSize:      imageSize,
		ImageID:        imageId, // docker.io/library/nginx:latest
		ImageDigest:    imageDigest,
		Cmd:            spec.Process.Args,
		Arguments:      spec.Process.Args,
		VolumeMounts:   volumeMounts,
		StorageType:    getContainerStorageType(isNfs, isCephfs, isHostPath),
		Path:           spec.Process.Cwd,
		ReservedCPU:    getCPUFromContainerd(spec),
		ReservedMemory: getMemoryFromContainerd(spec),
		Pid:            pid,
		K8sManaged:     k8sManaged,
		Environment:    util.DeIdentificationEnvs(spec.Process.Env),
		ProcessNumber:  len(processes),
		Processes:      getContainerProcessInfo(pid),
		User:           getUserFromContainerd(d, container.ID(), spec),
		Ports:          getContainerPorts(pid),
	}
	return tensorRawContainer, nil
}

func (d *ContainerdInfoManager) TryGetNetworkSettings(pid int) (*NetworkSettings, error) {
	netNS, err := InspectNetNS(pid, "/host")
	if err != nil {
		logging.Get().Error().Msgf("get netNS failed from  pid:%d ,err:%s", pid, err.Error())
		return nil, err
	}
	networkSettings, err := networkSettingsFromNative(netNS)
	if err != nil {
		logging.Get().Error().Msg("get networkSettings failed from netNS ,err:" + err.Error())
		return nil, err
	}
	return networkSettings, nil
}

func (d *ContainerdInfoManager) getContainerStatus(ctx context.Context, containerId string) (status int32, statusDesc string) {
	t, err := d.containerdCli.TaskService().Get(ctx, &tasks.GetRequest{
		ContainerID: containerId,
	})
	if err != nil {
		logging.Get().Error().Msgf("get task by container  failed. %v", err)
		return assetsPkg.Unknown, ""
	}
	return d.getCRIStatusFromContainerdStatus(t.Process.Status), taskPkg.Status_name[int32(t.Process.Status)]
}

// containerD Status To assets Status
/*func (d *ContainerdInfoManager) getContainerStatus(state task.Status) int32 {
	// github.com/containerd/containerd@v1.5.16/api/types/task/task.pb.go:33
	switch int32(state) {
	case 0:
		return assets.Dead
	case 1:
		return assets.Created
	case 2:
		return assets.Running
	case 3:
		return assets.Exited
	case 4, 5:
		return assets.Paused
	default:
		return assets.Dead
	}
}*/

func (d *ContainerdInfoManager) getCRIStatusFromContainerdStatus(state taskPkg.Status) int32 {
	switch state {
	case taskPkg.Status_UNKNOWN:
		return assetsPkg.Unknown
	case taskPkg.Status_CREATED:
		return assetsPkg.Created
	case taskPkg.Status_RUNNING:
		return assetsPkg.Running
	case taskPkg.Status_PAUSED:
		return assetsPkg.Running
	case taskPkg.Status_PAUSING:
		return assetsPkg.Running
	case taskPkg.Status_STOPPED:
		return assetsPkg.Exited
	default:
		logging.Get().Error().Msgf("not support containerd status,state:%d", state)
		return assetsPkg.Unknown
	}
}

func (d *ContainerdInfoManager) processEvents(container *model.TensorRawContainer, action string) {
	logging.Get().Info().Msgf("containerd processEvents containerId:%s,podName:%s,action:%s", container.ContainerID, container.PodName, action)
	if container.K8sManaged && container.ResourceName == "" && action == "start" {
		resName, resKind, err := d.store.GetPodOwner(container.Namespace, container.PodName)
		if err != nil {
			logging.Get().Warn().Err(err).Msg("containerd get pod owner err")
		} else {
			container.ResourceName = resName
			container.ResourceKind = resKind
			logging.Get().Info().Str("raw-container", "process event").Msgf("get pod owner of %s/%s/%s is %s/%s",
				container.Namespace, container.PodName, container.Name, resKind, resName)
		}
		pod, err := d.store.GetPod(container.Namespace, container.PodName)
		if err != nil {
			logging.Get().Warn().Msgf("containerd  get pod:%s/%s,pod: ,err %v", container.Namespace, container.Name, err)
		} else {
			var volumeMounts []model.Mounts
			var ports []model.Port
			for _, c := range pod.Spec.Containers {
				for _, m := range c.VolumeMounts {
					mount := model.Mounts{
						Name:        m.Name,
						MountPath:   m.MountPath,
						SubPath:     m.SubPath,
						SubPathExpr: m.SubPathExpr,
					}
					volumeMounts = append(volumeMounts, mount)
				}
				for _, p := range c.Ports {
					ports = append(ports, model.Port{
						Name:          p.Name,
						ContainerPort: p.ContainerPort,
						HostPort:      p.HostPort,
					})
				}
			}
			if pod.Status.PodIP != "" {
				container.IP = pod.Status.PodIP
			}
			container.Ports = utils.MergeContainerPorts(ports, container.Ports, container.IP)
			container.VolumeMounts = utils.MergeVolumeMounts(volumeMounts, container.VolumeMounts)
			if container.ImageDigest == "" {
				for _, con := range pod.Status.ContainerStatuses {
					if strings.Contains(con.ContainerID, container.ContainerID) {
						container.ImageName = con.Image
						/*
							case1:
									containerID: containerd://a08863714f070db8109577f5ac10dc2b5438d492cca5f1603ee9a0975a912554
							   		image: sha256:873127efbc8a791d06e85271d9a2ec4c5d58afdf612d490e24fb3ec68e891c8d
									imageID: sha256:873127efbc8a791d06e85271d9a2ec4c5d58afdf612d490e24fb3ec68e891c8d
							case2:
									containerID: docker://c7abff34f1ce2a4e7545e4897d41c627cac69d7fb43adb1ea3ffa3f085e3bd2b
									image: harbor.tensorsecurity.com/tensorsecurity/mysql:8.0.28-debian-10-r41
							    	imageID: docker-pullable://harbor.tensorsecurity.com/tensorsecurity/mysql@sha256:7686964fc33f106d98bf5430287a4aa250dc36146dd4ee4d3ebdd566b89d6663
						*/
						split := strings.Split(con.ImageID, "@")
						if len(split) == 2 {
							container.ImageDigest = split[1]
						} else if strings.HasPrefix(con.ImageID, "sha256:") {
							container.ImageDigest = con.ImageID
						}
						break
					}
				}
				if strings.HasPrefix(container.ImageName, "sha256:") {
					for _, con := range pod.Spec.Containers {
						if con.Name == container.Name {
							container.ImageName = con.Image
							break
						}
					}
				}
				logging.Get().Warn().Msgf("try find image from pod.containerId:%s imageName:%s,imageDigest:%s.", container.ContainerID, container.ImageName, container.ImageDigest)
			}
			//	找回 image tag：  因为containerd中, pod自定义标签 在容器运行时中没有
			container.ImageName = buildImageWithTag(container.ImageName, pod.Labels, container.Name)
			container.ImageUUID = model.GetImageUUID(container.ImageName, container.ImageDigest)
		}
	}
	switch action {
	case "create", "start":
		for _, handler := range d.handlers {
			handler.OnAdd(container)
		}
	case "pause", "resume":
		for _, handler := range d.handlers {
			handler.OnUpdate(nil, container)
		}
	case "exit", "delete":
		for _, handler := range d.handlers {
			handler.OnDelete(container)
		}
	default:
		logging.Get().Info().Msgf("received unknown event: %s", action)
	}
}

func (d *ContainerdInfoManager) RunCmd(ctx context.Context, containerId string, cmd []string) (resp string, err error) {
	//通用 向容器发送命令
	stdout, stderr, err := d.runClient.ExecSync(containerId, cmd, time.Second*5)
	if err != nil {
		return "", err
	}
	if len(stderr) == 0 {
		return string(stdout), nil
	}
	return fmt.Sprintf("stdout:%s\nstderr:%s", string(stdout), string(stderr)), nil
}

func (d *ContainerdInfoManager) addRetryContainer(namespace string, containerId string) {
	if containerId == "" || namespace == "" {
		return
	}
	logging.Get().Debug().Msgf("addRetryContainer: namespace:%s,containerId:%s", namespace, containerId)
	d.retryMapLock.Lock()
	d.retryMap[containerId] = &containerdRetryItem{
		namespace:   namespace,
		containerId: containerId,
		outTime:     time.Now().Add(time.Minute),
	}
	d.retryMapLock.Unlock()
}

func (d *ContainerdInfoManager) Retry() {
	timer := time.NewTicker(time.Minute)
	for range timer.C {
		//logging.Get().Debug().Msg("retry begin")
		var itemList []*containerdRetryItem
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
			d.retryOnce(context.Background(), item.namespace, item.containerId)
		}
	}
}

func (d *ContainerdInfoManager) retryOnce(ctx context.Context, namespace string, containerId string) {
	nsCtx := namespaces.WithNamespace(ctx, namespace)
	getResponse, err := d.containerdCli.TaskService().Get(nsCtx, &tasks.GetRequest{
		ContainerID: containerId,
	})
	if err != nil {
		if errdefs.IsNotFound(err) {
			logging.Get().Err(err).Msgf("retry: no running task found,containerId:%s", containerId)
			return
		}
		logging.Get().Err(err).Msgf("retry failed. containerId:%s", containerId)
		return
	}
	if getResponse.Process.ContainerID == "" {
		getResponse.Process.ContainerID = getResponse.Process.ID
	}
	container, err := d.containerdCli.LoadContainer(nsCtx, getResponse.Process.ContainerID)
	if err != nil {
		logging.Get().Err(err).Msgf("retry: get container failed. containerId:%s", containerId)
		return
	}
	containerDetail, err := d.buildContainerDetail(nsCtx, container, getResponse.Process)
	if err != nil {
		logging.Get().Error().Msgf("retry: ignore container:  err:%v ", err)
		return
	}
	if containerDetail == nil {
		logging.Get().Debug().Msgf("retry: ignore nil  container")
		return
	}
	logging.Get().Debug().Msgf("retry finish, containerId:%s", containerId)
	d.processEvents(containerDetail, "start")
}

func getCPUFromContainerd(spec *oci.Spec) (limit int64) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Debug().Msgf("get CPU limit failed,err:%v. ", r)
		}
	}()
	if spec.Linux.Resources.CPU.Period != nil && spec.Linux.Resources.CPU.Quota != nil {
		return *(spec.Linux.Resources.CPU.Quota) * 1000 / int64(*(spec.Linux.Resources.CPU.Period))
	}
	return 0
}

func getMemoryFromContainerd(spec *oci.Spec) int64 {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Debug().Msgf("get Memory limit failed,err:%v.", r)
		}
	}()
	return *spec.Linux.Resources.Memory.Limit
}

func getUserFromContainerd(d *ContainerdInfoManager, containerId string, spec *oci.Spec) string {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Info().Msgf("get user info failed,err:%v. stack: %s", r, debug.Stack())
		}
	}()
	if spec.Process.User.UID == 0 {
		return "root"
	}
	ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)

	resp, err := d.RunCmd(ctx, containerId, []string{"/bin/sh", "-c", "whoami"})
	logging.Get().Error().Msgf("get user by cmd . output:%s, uid:%d, containerId:%s", resp, spec.Process.User.UID, containerId)
	if err == nil && resp != "" && !strings.Contains(resp, "stderr:") {
		return strings.TrimSuffix(resp, "\n")
	}
	bytes, err := json.Marshal(spec.Process.User)
	if err != nil {
		return ""
	}
	return string(bytes)
}

// InspectNetNS  prefix: 路径映射前缀
func InspectNetNS(pid int, prefix string) (*native.NetNS, error) {
	nsPath := fmt.Sprintf(filepath.Join(prefix, "/proc/%d/ns/net"), pid)
	res := &native.NetNS{}
	fn := func(_ ns.NetNS) error {
		intf, err := net.Interfaces()
		if err != nil {
			return err
		}
		res.Interfaces = make([]native.NetInterface, len(intf))
		for i, f := range intf {
			x := native.NetInterface{
				Interface: f,
			}
			if f.HardwareAddr != nil {
				x.HardwareAddr = f.HardwareAddr.String()
			}
			if x.Interface.Flags.String() != "0" {
				x.Flags = strings.Split(x.Interface.Flags.String(), "|")
			}
			if addrs, err := x.Interface.Addrs(); err == nil {
				x.Addrs = make([]string, len(addrs))
				for j, a := range addrs {
					x.Addrs[j] = a.String()
				}
			}
			res.Interfaces[i] = x
		}
		res.PrimaryInterface = determinePrimaryInterface(res.Interfaces)
		return nil
	}
	if err := ns.WithNetNSPath(nsPath, fn); err != nil {
		return nil, err
	}
	return res, nil
}

// determinePrimaryInterface returns a net.Interface.Index value, not a slice index.
// Zero means no primary interface was detected.
func determinePrimaryInterface(interfaces []native.NetInterface) int {
	for _, f := range interfaces {
		if f.Interface.Flags&net.FlagLoopback == 0 && f.Interface.Flags&net.FlagUp != 0 && !strings.HasPrefix(f.Name, "lo") {
			return f.Index
		}
	}
	return 0
}

type NetworkSettings struct {
	Ports *nat.PortMap `json:",omitempty"`
	DefaultNetworkSettings
	Networks map[string]*NetworkEndpointSettings
}

// DefaultNetworkSettings is from https://github.com/moby/moby/blob/v20.10.1/api/types/types.go#L405-L414
type DefaultNetworkSettings struct {
	// TODO EndpointID          string // EndpointID uniquely represents a service endpoint in a Sandbox
	// TODO Gateway             string // Gateway holds the gateway address for the network
	GlobalIPv6Address   string // GlobalIPv6Address holds network's global IPv6 address
	GlobalIPv6PrefixLen int    // GlobalIPv6PrefixLen represents mask length of network's global IPv6 address
	IPAddress           string // IPAddress holds the IPv4 address for the network
	IPPrefixLen         int    // IPPrefixLen represents mask length of network's IPv4 address
	// TODO IPv6Gateway         string // IPv6Gateway holds gateway address specific for IPv6
	MacAddress string // MacAddress holds the MAC address for the network
}

// NetworkEndpointSettings is from https://github.com/moby/moby/blob/v20.10.1/api/types/network/network.go#L49-L65
type NetworkEndpointSettings struct {
	// Configurations
	// TODO IPAMConfig *EndpointIPAMConfig
	// TODO Links      []string
	// TODO Aliases    []string
	// Operational data
	// TODO NetworkID           string
	// TODO EndpointID          string
	// TODO Gateway             string
	IPAddress   string
	IPPrefixLen int
	// TODO IPv6Gateway         string
	GlobalIPv6Address   string
	GlobalIPv6PrefixLen int
	MacAddress          string
	// TODO DriverOpts          map[string]string
}

func networkSettingsFromNative(n *native.NetNS) (*NetworkSettings, error) {
	if n == nil {
		return nil, nil
	}
	res := &NetworkSettings{
		Networks: make(map[string]*NetworkEndpointSettings),
	}
	var primary *NetworkEndpointSettings
	for _, x := range n.Interfaces {
		if x.Interface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if x.Interface.Flags&net.FlagUp == 0 {
			continue
		}
		nes := &NetworkEndpointSettings{}
		nes.MacAddress = x.HardwareAddr

		for _, a := range x.Addrs {
			ip, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				logrus.WithError(err).WithField("name", x.Name).Warnf("failed to parse %q", a)
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if ip4 := ip.To4(); ip4 != nil {
				nes.IPAddress = ip4.String()
				nes.IPPrefixLen = ones
			} else if ip16 := ip.To16(); ip16 != nil {
				nes.GlobalIPv6Address = ip16.String()
				nes.GlobalIPv6PrefixLen = ones
			}
		}
		// TODO: set CNI name when possible
		fakeDockerNetworkName := fmt.Sprintf("unknown-%s", x.Name)
		res.Networks[fakeDockerNetworkName] = nes

		if x.Index == n.PrimaryInterface {
			primary = nes
		}

	}
	if primary != nil {
		res.DefaultNetworkSettings.MacAddress = primary.MacAddress
		res.DefaultNetworkSettings.IPAddress = primary.IPAddress
		res.DefaultNetworkSettings.IPPrefixLen = primary.IPPrefixLen
		res.DefaultNetworkSettings.GlobalIPv6Address = primary.GlobalIPv6Address
		res.DefaultNetworkSettings.GlobalIPv6PrefixLen = primary.GlobalIPv6PrefixLen
	}
	return res, nil
}

// nfs ceph
func getContainerStorageType(isNfs, isCephfs, isHostPath bool) string {
	var storageType []string

	if isNfs {
		storageType = append(storageType, "nfs")
	}
	if isCephfs {
		storageType = append(storageType, "cephfs")
	}
	if isHostPath {
		storageType = append(storageType, "hostpath")
	}
	return strings.Join(storageType, "、")
}

func buildImageWithTag(imageName string, labels map[string]string, containerName string) string {
	if !strings.Contains(imageName, "@") {
		return imageName
	}
	logging.Get().Info().Msgf("buildImageWithTag: find imageName:%s,containerName:%s", imageName, containerName)
	if len(labels) == 0 {
		logging.Get().Warn().Msgf("buildImageWithTag: label is empty ,can't find imageLabel")
		return imageName
	}
	sprintf := fmt.Sprintf("%s-image-tag", containerName)
	ima, isOk := labels[sprintf]
	logging.Get().Info().Msgf("buildImageWithTag: labelKey[%s:%s]", sprintf, ima)
	if !isOk {
		return imageName
	}
	split := strings.Split(imageName, "@")
	if len(split) == 2 {
		return split[0] + ":" + ima
	}
	return imageName
}

func (d *ContainerdInfoManager) isDeleteEvent(action string) bool {
	if action == "exit" || action == "delete" {
		return true
	}
	return false
}

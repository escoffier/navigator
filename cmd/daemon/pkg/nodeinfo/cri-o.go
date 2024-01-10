package nodeinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	cri "k8s.io/cri-api/pkg/apis"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

var crioPollingDuration = time.Minute * 5

type CRIOInfoManager struct {
	runClient     cri.RuntimeService
	imageClient   cri.ImageManagerService
	hostIP        string
	hostName      string
	containerData map[string]int64 // map[containerId]time //缓存最近90s的事件
	handlers      []ContainerEventHandler
	agent         *containerassets.Agent
	store         containerassets.PodCache
	clusterKey    string
	mqReady       atomic.Bool
	sync.RWMutex
	runningContainerMap sync.Map // 缓存running的容器id
	synced              atomic.Bool
}

// unix://xxx
func GetCRIOdAddr() string {
	uri := os.Getenv("CRIO_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix:///var/run/crio/crio.sock"
	}
	return uri
}

func NewCRIOInfoManager(clusterKey, hostName, hostIP string, agent *containerassets.Agent) (*CRIOInfoManager, error) {
	uri := GetCRIOdAddr()
	runClient, err := remote.NewRemoteRuntimeService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("crio new NewRemoteRuntimeService failed, %v", err)
	}
	imageClient, err := remote.NewRemoteImageService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("crio new NewRemoteImageService failed, %v", err)
	}

	crioInfoManager := CRIOInfoManager{
		runClient:     runClient,
		imageClient:   imageClient,
		hostIP:        hostIP,
		hostName:      hostName,
		containerData: make(map[string]int64, 30),
		agent:         agent,
		clusterKey:    clusterKey,
	}
	crioInfoManager.mqReady.Store(false)
	go func() {
		defer func() {
			r := recover()
			if r != nil {
				logging.Get().Error().Str("CRI", ContainerdType).Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		crioInfoManager.clearContainerTimeoutData()
	}()

	return &crioInfoManager, nil
}

func (d *CRIOInfoManager) Synced() bool {
	return d.synced.Load()
}

func (c *CRIOInfoManager) clearContainerTimeoutData() {
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

			c.Lock()
			defer c.Unlock()

			if count >= 60 { // if a map keeps a stable size but is with continuous add or delete, it should be reconstructed after a period of time to prevent memory leak
				newMap := make(map[string]int64, len(c.containerData))
				for containerID, timestamp := range c.containerData {
					if nowTime.Unix()-timestamp >= containerIDTimeoutSec {
						continue
					}
					newMap[containerID] = timestamp
				}
				c.containerData = newMap
				count = 0
			} else {
				for containerID, timestamp := range c.containerData {
					if nowTime.Unix()-timestamp < containerIDTimeoutSec {
						continue
					}
					delete(c.containerData, containerID)
				}
				count++
			}

		}(now)
	}
}

func (c *CRIOInfoManager) GetContainerPid(containerID string) (int, string, error) {
	containerID = strings.TrimPrefix(containerID, "cri-o://")
	r, err := c.runClient.ContainerStatus(containerID, true)
	if err != nil {
		return 0, "", errors.Errorf("get container status by crio failed, %v", err)
	}

	info := r.GetInfo()
	value := info["info"]
	data := make(map[string]interface{})
	err = json.Unmarshal([]byte(value), &data)
	if err != nil {
		return 0, "", errors.Errorf("cri-o json unmarshal failed, %v", err)
	}

	pid := data["pid"]
	if pid == nil {
		return 0, "", errors.Errorf("cri-o container status have not find pid")
	}

	fpid := pid.(float64)

	return int(fpid), containerID, nil
}

func (c *CRIOInfoManager) ListenEvents(saveData SaveContainerDataFunc) {
	ticker := time.NewTicker(crioPollingDuration)
	defer ticker.Stop()
	for t := range ticker.C {
		containers, err := c.runClient.ListContainers(&runtimeapi.ContainerFilter{
			State: &runtimeapi.ContainerStateValue{
				State: runtimeapi.ContainerState_CONTAINER_RUNNING,
			},
		})
		if err != nil {
			logging.Get().Err(err).Msg("crio ListContainers failed.")
			continue
		}
		var exitContainerIdList []string
		newContainerMap := make(map[string]*runtimeapi.Container)
		currentIdMap := make(map[string]struct{})
		for _, container := range containers {
			currentIdMap[container.Id] = struct{}{}
			_, ok := c.runningContainerMap.Load(container.Id)
			if !ok {
				newContainerMap[container.Id] = container
				c.runningContainerMap.Store(container.Id, "")
				saveData(container.Id, t.Unix())
			}
		}
		c.runningContainerMap.Range(func(key, value any) bool {
			id := key.(string)
			_, ok := currentIdMap[id]
			if !ok {
				exitContainerIdList = append(exitContainerIdList, id)
				c.runningContainerMap.Delete(key)
			}
			return true
		})

		if !c.mqReady.Load() || !ExportRawContainer {
			logging.Get().Warn().Msg("mq is not ready or ExportRawContainer is false")
			continue
		}
		logging.Get().Debug().Msgf("crio compare result: newContainer count:%d, existContainer count:%d", len(newContainerMap), len(exitContainerIdList))
		// add
		for _, container := range newContainerMap {
			detail, err := c.buildContainerDetail(container)
			if err != nil {
				logging.Get().Info().Msgf("ignore container: %s , err:%v ", container.Id, err)
				continue
			}
			if detail == nil {
				continue
			}
			c.processEvents(detail, "create")
		}
		for _, id := range exitContainerIdList {
			contain := &model.TensorRawContainer{ContainerID: id}
			c.processEvents(contain, "delete")
		}
	}
}

func (c *CRIOInfoManager) saveContainerData(containerID string, timestamp int64) {
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
	c.Lock()
	defer c.Unlock()
	c.containerData[containerID] = timestamp
}

func (c *CRIOInfoManager) FindContainerCacheData(containerID string) (int64, bool) {
	if len(containerID) == 0 {
		return 0, false
	}
	if len(containerID) > shortContainerIDLength {
		containerID = containerID[0:shortContainerIDLength]
	}
	c.RLock()
	defer c.RUnlock()
	timestamp, ok := c.containerData[containerID]
	return timestamp, ok
}

func (c *CRIOInfoManager) Start() error {
	t := time.Now()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		logging.Get().Warn().Msg("start CRI-O InfoManager")
		if ExportRawContainer {
			// check if mq ready
			c.agent.HandlerContainerSyncCheck(context.Background(), c.clusterKey, c.hostName)
			c.agent.MqReady(true)
			c.mqReady.Store(true)

			c.listAll()
			c.agent.HandlerContainerSync(context.Background(), c.clusterKey, c.hostName, t)
			c.synced.Store(true)
		}
		// handle containerd events
		c.ListenEvents(c.saveContainerData)
	}()
	return nil
}

func (c *CRIOInfoManager) AddEventHandler(handler ContainerEventHandler) {
	c.handlers = append(c.handlers, handler)
}

func (c *CRIOInfoManager) SetPodStore(store containerassets.PodCache) {
	c.store = store
}

func (c *CRIOInfoManager) listAll() {
	containers, err := c.runClient.ListContainers(&runtimeapi.ContainerFilter{
		State: &runtimeapi.ContainerStateValue{
			State: runtimeapi.ContainerState_CONTAINER_RUNNING,
		},
	})

	if err != nil {
		logging.Get().Err(err).Msg("crio ListContainers failed.")
	}
	for _, container := range containers {
		logging.Get().Info().Msg("containerId:" + container.Id)
		tensorRawContainer, err := c.buildContainerDetail(container)
		if err != nil {
			logging.Get().Info().Msgf("ignore container:  err:%v ", err)
			continue
		}
		if tensorRawContainer == nil {
			continue
		}
		c.runningContainerMap.Store(container.Id, "")
		c.processEvents(tensorRawContainer, "create")
	}
}

func (c *CRIOInfoManager) buildContainerDetail(container *runtimeapi.Container) (*model.TensorRawContainer, error) {
	create := time.Unix(0, container.CreatedAt)

	containerStatus, containerInfo, err := GetCrioContainerDetail(c.runClient, container.Id, true)
	if err != nil {

	}
	var (
		name      string
		podName   string
		namespace string
		podUid    string
		digest    string
	)
	if containerStatus.Labels != nil {
		name = containerStatus.Labels["io.kubernetes.container.name"]
		podName = containerStatus.Labels["io.kubernetes.pod.name"]
		namespace = containerStatus.Labels["io.kubernetes.pod.namespace"]
		podUid = containerStatus.Labels["io.kubernetes.pod.uid"]
	}
	if strings.Contains(containerStatus.ImageRef, "@sha256:") {
		split := strings.Split(containerStatus.ImageRef, "@")
		if len(split) == 2 {
			digest = split[1]
		}
	}
	imageStatus, imageInfo, err := GetCrioImageDetail(c.imageClient, container.Image.Image, true)
	runtime := containerInfo.RuntimeSpec
	pid := containerInfo.Pid

	volumeMounts := make([]model.Mounts, 0, len(runtime.Mounts))
	var isNfs, isCephfs, isHostPath bool
	for _, m := range runtime.Mounts {
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
	var k8sManaged bool
	if podName != "" {
		k8sManaged = true
	}
	var user string
	if runtime.Process.User.Uid == 0 {
		user = "root"
	} else {
		ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
		resp, err := c.RunCmd(ctx, container.Id, []string{"/bin/sh", "-c", "whoami"})
		logging.Get().Error().Msgf("get user by cmd . output:%s,uid:%d,containerId:%s", resp, runtime.Process.User.Uid, container.Id)
		if err == nil && resp != "" && !strings.Contains(resp, "stderr:") {
			user = strings.TrimSuffix(resp, "\n")
		} else {
			userByte, err := json.Marshal(runtime.Process.User)
			if err != nil {
				logging.Get().Err(err).Msg("json Marshal User failed.")
			}
			user = string(userByte)
		}
	}
	networkSettings, err := c.TryGetNetworkSettings(pid)
	if err != nil {
		logging.Get().Error().Msg("TryGetNetworkSettings failed,err:" + err.Error())
		networkSettings = &NetworkSettings{}
	}
	reslult := model.TensorRawContainer{
		CreatedAt:   create,
		UpdatedAt:   time.Now(),
		Status:      c.translateState(container.State),
		ContainerID: container.Id,
		NetworkMode: "container",
		IP:          networkSettings.IPAddress,
		IPV6:        networkSettings.GlobalIPv6Address,
		// Gateway:        "",
		Mac:            networkSettings.MacAddress,
		Name:           name,
		FullName:       name,
		PodName:        podName,
		PodUid:         podUid,
		Namespace:      namespace,
		ClusterKey:     c.clusterKey,
		NodeName:       c.hostName,
		NodeIP:         c.hostIP,
		Labels:         containerStatus.Labels,
		ImageName:      containerStatus.Image.Image,
		ImageID:        containerStatus.ImageRef,
		ImageDigest:    digest,
		ImageSize:      int64(imageStatus.Size()),
		ImageCreated:   imageInfo.ImageSpec.Created.Format(time.RFC3339Nano),
		Cmd:            runtime.Process.Args,
		Arguments:      runtime.Process.Args,
		Environment:    runtime.Process.Env,
		VolumeMounts:   volumeMounts,
		StorageType:    getContainerStorageType(isNfs, isCephfs, isHostPath),
		Path:           runtime.Process.Cwd,
		ReservedCPU:    getCPUFromCRIO(runtime),
		ReservedMemory: getMemoryFromCRIO(runtime),
		Pid:            pid,
		K8sManaged:     k8sManaged,
		// ProcessNumber:  ,
		Processes: getContainerProcessInfo(pid),
		Ports:     getContainerPorts(pid),
		User:      user,
	}
	return &reslult, nil
}

func (c *CRIOInfoManager) processEvents(container *model.TensorRawContainer, action string) {
	logging.Get().Info().Msgf("crio processEvents containerId:%s,podName:%s,action:%s", container.ContainerID, container.PodName, action)
	if container.K8sManaged && container.ResourceName == "" && !isDeleteEvent(action) {
		resName, resKind, err := c.store.GetPodOwner(container.Namespace, container.PodName)
		if err != nil {
			logging.Get().Warn().Err(err).Msg("containerd get pod owner err")
		} else {
			container.ResourceName = resName
			container.ResourceKind = resKind
		}
		pod, err := c.store.GetPod(container.Namespace, container.PodName)
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
			//	找回 image tag：  因为crio中, pod自定义标签 在容器运行时中没有
			container.ImageName = buildImageWithTag(container.ImageName, pod.Labels, container.Name)
			container.ImageUUID = model.GetImageUUID(container.ImageName, container.ImageDigest)
		}
	}
	switch action {
	case "create", "start":
		for _, handler := range c.handlers {
			handler.OnAdd(container)
		}
	case "pause", "resume":
		for _, handler := range c.handlers {
			handler.OnUpdate(nil, container)
		}
	case "stop", "kill", "delete":
		for _, handler := range c.handlers {
			handler.OnDelete(container)
		}
	default:
		logging.Get().Info().Msgf("received unknown event: %s", action)
	}
}

func (c *CRIOInfoManager) translateState(state runtimeapi.ContainerState) int32 {
	switch state {
	case runtimeapi.ContainerState_CONTAINER_CREATED:
		return assets.Created
	case runtimeapi.ContainerState_CONTAINER_RUNNING:
		return assets.Running
	case runtimeapi.ContainerState_CONTAINER_EXITED:
		return assets.Exited
	case runtimeapi.ContainerState_CONTAINER_UNKNOWN:
		return assets.Dead
	default:
		return assets.All
	}
}

func getCPUFromCRIO(spec RuntimeSpec) (limit int64) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Debug().Msgf("get CPU limit failed,err:%v. ", r)
		}
	}()
	if spec.Linux.Resources.Cpu.Period != 0 && spec.Linux.Resources.Cpu.Quota != 0 {
		return int64(spec.Linux.Resources.Cpu.Quota) * 1000 / int64(spec.Linux.Resources.Cpu.Period)
	}
	return 0
}

func getMemoryFromCRIO(spec RuntimeSpec) int64 {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Debug().Msgf("get Memory limit failed,err:%v.", r)
		}
	}()
	return int64(spec.Linux.Resources.Memory.Limit)
}

func (c *CRIOInfoManager) TryGetNetworkSettings(pid int) (*NetworkSettings, error) {
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

func (c *CRIOInfoManager) RunCmd(ctx context.Context, containerId string, cmd []string) (resp string, err error) {
	// 向容器发送命令
	stdout, stderr, err := c.runClient.ExecSync(containerId, cmd, time.Second*5)
	if err != nil {
		return "", err
	}
	if len(stderr) == 0 {
		return string(stdout), nil
	}
	return fmt.Sprintf("stdout:%s\nstderr:%s", string(stdout), string(stderr)), nil
}

// GetCrioImageDetail  获取crio image信息，verbose 是否需要额外详细信息 ，verbose is false, *ImageInfo  return nil
func GetCrioImageDetail(imageClient cri.ImageManagerService, image string, verbose bool) (*runtimeapi.Image, *ImageInfo, error) {
	imageStatusResponse, err := imageClient.ImageStatus(&runtimeapi.ImageSpec{
		Image: image,
	}, verbose)
	if err != nil {
		return nil, nil, fmt.Errorf("get ImageStatus failed,%v", err)
	}
	imageInfo := &ImageInfo{}
	if verbose {
		err = json.Unmarshal([]byte(imageStatusResponse.Info["info"]), imageInfo)
		if err != nil {
			return nil, nil, fmt.Errorf("json unmarshal ImageSpec failed.%v", err)
		}
	}
	return imageStatusResponse.Image, imageInfo, nil
}

// GetCrioContainerDetail 获取crio container信息，verbose 是否需要额外详细信息,verbose为false时，*ContainerInfo  return nil
func GetCrioContainerDetail(runClient cri.RuntimeService, containerId string, verbose bool) (*runtimeapi.ContainerStatus, *ContainerInfo, error) {
	containerStatusResponse, err := runClient.ContainerStatus(containerId, verbose)
	if err != nil {
		logging.Get().Err(err).Msg("get ContainerStatus failed.")
		return nil, nil, err
	}

	containerInfo := &ContainerInfo{}
	if verbose {

		err = json.Unmarshal([]byte(containerStatusResponse.Info["info"]), containerInfo)
		if err != nil {
			logging.Get().Err(err).Msg("json unmarshal containerInfoMap failed.")
			return nil, nil, err
		}
	}
	return containerStatusResponse.Status, containerInfo, nil
}

// field may not full
type ImageInfo struct {
	ImageSpec struct {
		Architecture string `json:"architecture"`
		Config       struct {
			Cmd    []string          `json:"Cmd"`
			Env    []string          `json:"Env"`
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
		Created time.Time `json:"created"`
		History []struct {
			Created    time.Time `json:"created"`
			CreatedBy  string    `json:"created_by"`
			EmptyLayer bool      `json:"empty_layer,omitempty"`
			Comment    string    `json:"comment,omitempty"`
		} `json:"history"`
		Os     string `json:"os"`
		Rootfs struct {
			DiffIds []string `json:"diff_ids"`
			Type    string   `json:"type"`
		} `json:"rootfs"`
	} `json:"imageSpec"`
	Labels map[string]string `json:"labels"`
}

// field may not full
type ContainerInfo struct {
	Pid         int         `json:"pid"`
	Privileged  bool        `json:"privileged"`
	RuntimeSpec RuntimeSpec `json:"runtimeSpec"`
	SandboxID   string      `json:"sandboxID"`
}
type RuntimeSpec struct {
	Annotations map[string]string `json:"annotations"`
	Hostname    string            `json:"hostname"`
	Linux       struct {
		CgroupsPath string   `json:"cgroupsPath"`
		MaskedPaths []string `json:"maskedPaths"`
		Namespaces  []struct {
			Type string `json:"type"`
			Path string `json:"path,omitempty"`
		} `json:"namespaces"`
		ReadonlyPaths []string `json:"readonlyPaths"`
		Resources     struct {
			Cpu struct {
				Period int `json:"period"`
				Quota  int `json:"quota"`
				Shares int `json:"shares"`
			} `json:"cpu"`
			Memory struct {
				Limit int `json:"limit"`
				Swap  int `json:"swap"`
			} `json:"memory"`
			Devices []struct {
				Access string `json:"access"`
				Allow  bool   `json:"allow"`
			} `json:"devices"`
			HugepageLimits []struct {
				Limit    int    `json:"limit"`
				PageSize string `json:"pageSize"`
			} `json:"hugepageLimits"`
			Pids struct {
				Limit int `json:"limit"`
			} `json:"pids"`
		} `json:"resources"`
	} `json:"linux"`
	Mounts []struct {
		Destination string   `json:"destination"`
		Options     []string `json:"options"`
		Source      string   `json:"source"`
		Type        string   `json:"type"`
	} `json:"mounts"`
	OciVersion string `json:"ociVersion"`
	Process    struct {
		Args         []string `json:"args"`
		Capabilities struct {
			Bounding    []string `json:"bounding"`
			Effective   []string `json:"effective"`
			Inheritable []string `json:"inheritable"`
			Permitted   []string `json:"permitted"`
		} `json:"capabilities"`
		Cwd         string   `json:"cwd"`
		Env         []string `json:"env"`
		OomScoreAdj int      `json:"oomScoreAdj"`
		User        struct {
			Gid int `json:"gid"`
			Uid int `json:"uid"`
		} `json:"user"`
	} `json:"process"`
	Root struct {
		Path string `json:"path"`
	} `json:"root"`
}

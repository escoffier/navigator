package crio

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/logging"
	cri "k8s.io/cri-api/pkg/apis"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

const (
	version                  = "crio"
	containerdRequestTimeout = 20
	exportImageTimeout       = 1800 // long timeout for big image
	imageTarTimeoutENV       = "IMG_TAR_TIMEOUT_ENV"
	containerIDTimeoutSec    = int64(90)
	monitorDuration          = time.Minute * 1 // 轮询间隔时间，模拟事件通知功能
)

type crioDriverConfig struct {
	Endpoint string `json:"endpoint"`
}

type crioDriver struct {
	config              *crioDriverConfig
	evCallback          container.EventCallback
	runClient           cri.RuntimeService
	imageClient         cri.ImageManagerService
	runningContainerMap map[string]int64 // map[containerId]time   缓存running状态的containerId
	deleteCount         int
	sync.Mutex
}

func init() {
	err := container.Register(version, NewCRIODriver)
	if err != nil {
		logging.Get().Err(err).Msg("register runtime crio driver failed")
		return
	}

	logging.Get().Debug().Msg("runtime crio driver register success")
}

func NewCRIODriver(config container.RuntimeConfig) (container.Runtime, error) {
	var d crioDriver

	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.Get().
			Err(err).
			Interface("options", config.Options).
			Msg("runtime crio marshal config failed")
		return nil, err
	}

	conf := new(crioDriverConfig)
	if err := json.Unmarshal(byt, conf); err != nil {
		logging.Get().
			Err(err).
			Bytes("config", byt).
			Msg("runtime crio Unmarshal config failed")
		return nil, err
	}

	d.config = conf
	d.config.Endpoint = strings.TrimSpace(d.config.Endpoint)
	if d.config.Endpoint != "" {
		os.Setenv("CRIO_HOST", d.config.Endpoint)
	}
	uri := nodeinfo.GetCRIOdAddr()
	// crio client
	runClient, err := remote.NewRemoteRuntimeService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("crio new NewRemoteRuntimeService failed, %v", err)
	}
	imageClient, err := remote.NewRemoteImageService(uri, 2*time.Second)
	if err != nil {
		return nil, errors.Errorf("crio new NewRemoteImageService failed, %v", err)
	}

	d.runClient = runClient
	d.imageClient = imageClient
	d.runningContainerMap = make(map[string]int64, 30)
	go func() {
		defer func() {
			r := recover()
			if r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		d.clearContainerTimeoutData()
	}()
	return &d, nil
}

// TODO
func (c *crioDriver) MonitorEvent(cb container.EventCallback) error {
	ticker := time.NewTicker(monitorDuration)
	defer ticker.Stop()
	for t := range ticker.C {
		c.Lock()
		containers, err := c.runClient.ListContainers(&runtimeapi.ContainerFilter{
			State: &runtimeapi.ContainerStateValue{
				State: runtimeapi.ContainerState_CONTAINER_RUNNING,
			},
		})
		if err != nil {
			logging.Get().Err(err).Msg("crio ListContainers failed.")
			c.Unlock()
			continue
		}
		timestamp := t.Unix()
		var exitContainerIdList []string
		newContainerMap := make(map[string]*runtimeapi.Container)
		currentIdMap := make(map[string]struct{})
		for _, con := range containers {
			currentIdMap[con.Id] = struct{}{}
			_, ok := c.runningContainerMap[con.Id]
			if !ok {
				newContainerMap[con.Id] = con
				c.runningContainerMap[con.Id] = timestamp
			}
		}
		for id, _ := range c.runningContainerMap {
			_, ok := currentIdMap[id]
			if !ok {
				exitContainerIdList = append(exitContainerIdList, id)
			}
		}

		logging.Get().Debug().Msgf("crio compare result: newContainer count:%d, existContainer count:%d", len(newContainerMap), len(exitContainerIdList))
		// delete
		c.deleteCount += len(exitContainerIdList)
		for _, id := range exitContainerIdList {
			delete(c.runningContainerMap, id)
			ev := &container.EventMessage{
				Event:         "delete",
				Type:          "container",
				Time:          timestamp,
				ContainerInfo: container.ContainerMeta{ID: id},
			}
			go cb(ev)
		}
		c.Unlock()
		// add
		for _, con := range newContainerMap {
			detail, err := c.GetContainerMeta("", con.Id)
			if err != nil {
				logging.Get().Info().Msgf("ignore new container: %s , err:%v ", con.Id, err)
				continue
			}
			ev := &container.EventMessage{
				Event:         "start",
				Type:          "container",
				Time:          timestamp,
				ContainerInfo: detail,
			}
			go cb(ev)
		}
	}
	return nil
}

func (c *crioDriver) StopMonitorEvent() error {
	return nil
}

func (c *crioDriver) GetContainerMeta(namespace string, containerID string) (container.ContainerMeta, error) {
	containerStatus, containerInfo, err := nodeinfo.GetCrioContainerDetail(c.runClient, containerID, true)
	if err != nil {
		return container.ContainerMeta{}, fmt.Errorf("crio GetContainerMeta GetCrioContainerDetail failed.%v", err)
	}
	if containerStatus.Labels == nil {
		containerStatus.Labels = make(map[string]string)
	}
	var name string
	if containerStatus.GetMetadata() != nil {
		name = containerStatus.GetMetadata().GetName()
	}
	if name == "" {
		name = containerStatus.Labels["io.kubernetes.container.name"]
	}
	image, _, err := nodeinfo.GetCrioImageDetail(c.imageClient, containerStatus.Image.Image, false)
	if err != nil {
		return container.ContainerMeta{}, fmt.Errorf("crio GetContainerMeta GetCrioImageDetail failed.%v", err)
	}

	meta := container.ContainerMeta{
		ID:            containerID,
		Name:          containerStatus.GetMetadata().GetName(),
		ProcessID:     containerInfo.Pid,
		ImageID:       containerStatus.Image.Image,
		ImageDigest:   image.RepoDigests,
		State:         c.translateState(runtimeapi.ContainerState(runtimeapi.ContainerState_value[string(containerStatus.State)])),
		ImageRepoTags: image.RepoTags,
		PodUID:        containerStatus.Labels["io.kubernetes.pod.uid"],
		GraphDriver:   types.GraphDriverData{},
		Labels:        containerStatus.Labels,
	}
	return meta, nil
}

func (c *crioDriver) ListRunningContainers() ([]container.Container, error) {
	containers, err := c.runClient.ListContainers(&runtimeapi.ContainerFilter{
		State: &runtimeapi.ContainerStateValue{
			State: runtimeapi.ContainerState_CONTAINER_RUNNING,
		},
	})

	if err != nil {
		logging.Get().Err(err).Msg("crio ListContainers failed.")
	}
	var runningContainers []container.Container

	for _, con := range containers {
		logging.Get().Info().Msg("containerId:" + con.Id)
		containerStatusResponse, err := c.runClient.ContainerStatus(con.Id, true)
		if err != nil {
			logging.Get().Err(err).Msg("get ContainerStatus failed.")
			return nil, err
		}
		var containerInfo nodeinfo.ContainerInfo
		err = json.Unmarshal([]byte(containerStatusResponse.Info["info"]), &containerInfo)
		if err != nil {
			logging.Get().Err(err).Msg("json unmarshal containerInfoMap failed.")
			return nil, err
		}
		var name string
		if containerStatusResponse.Status.Labels != nil {
			name = containerStatusResponse.Status.Labels["io.kubernetes.container.name"]
		}
		runningContainers = append(runningContainers, container.Container{
			ID:      con.Id,
			Names:   []string{name},
			Image:   con.Image.Image,
			ImageID: con.Image.Image,
			Command: strings.Join(containerInfo.RuntimeSpec.Process.Args, " "),
			Created: con.CreatedAt,
			Labels:  containerStatusResponse.Status.Labels,
			Status:  c.translateState(con.State),
		})
	}

	return runningContainers, nil
}
func (c *crioDriver) translateState(state runtimeapi.ContainerState) string {
	switch state {
	case runtimeapi.ContainerState_CONTAINER_CREATED:
		return assets.GetRawContainerStatus(assets.Created)
	case runtimeapi.ContainerState_CONTAINER_RUNNING:
		return assets.GetRawContainerStatus(assets.Running)
	case runtimeapi.ContainerState_CONTAINER_EXITED:
		return assets.GetRawContainerStatus(assets.Exited)
	case runtimeapi.ContainerState_CONTAINER_UNKNOWN:
		return assets.GetRawContainerStatus(assets.Dead)
	default:
		return assets.GetRawContainerStatus(assets.All)
	}
}

func (c *crioDriver) ListImages() ([]container.ImageSummary, error) {
	images, err := c.imageClient.ListImages(nil)
	if err != nil {
		return nil, err
	}
	var imageList []container.ImageSummary
	for _, image := range images {
		imageList = append(imageList, container.ImageSummary{
			// Created:     0,
			ID: image.Id,
			// Labels:
			RepoDigests: image.RepoDigests,
			RepoTags:    image.RepoTags,
		})
	}
	return imageList, nil
}

func (c *crioDriver) GetContainerInspect(containerID string) (container.ContainerInspect, error) {
	panic("implement me")
}

func (c *crioDriver) GetImageInspect(namespace string, imageID string) (container.ImageInspect, error) {
	image, imageInfo, err := nodeinfo.GetCrioImageDetail(c.imageClient, imageID, true)
	if err != nil {
		return container.ImageInspect{}, fmt.Errorf("crio GetImageInspect failed. %v", err)
	}
	var fs container.RootFS
	fs.Type = imageInfo.ImageSpec.Rootfs.Type
	for _, d := range imageInfo.ImageSpec.Rootfs.DiffIds {
		fs.Layers = append(fs.Layers, d)
	}
	result := container.ImageInspect{
		ID:           imageID,
		RepoTags:     image.GetRepoTags(),
		RepoDigests:  image.GetRepoDigests(),
		Created:      imageInfo.ImageSpec.Created.Format(time.RFC3339Nano),
		Env:          imageInfo.ImageSpec.Config.Env,
		Cmd:          imageInfo.ImageSpec.Config.Cmd,
		User:         "",
		Architecture: imageInfo.ImageSpec.Architecture,
		Variant:      "",
		Os:           imageInfo.ImageSpec.Os,
		OsVersion:    "",
		Size:         int64(image.Size_),
		VirtualSize:  int64(image.Size_),
		// GraphDriver:  container.GraphDriverData{},
		RootFS: fs,
	}
	return result, nil
}

func (c *crioDriver) ImageHistory(namespace string, imageID string) ([]container.HistoryResponseItem, error) {
	_, imageInfo, err := nodeinfo.GetCrioImageDetail(c.imageClient, imageID, true)
	if err != nil {
		return nil, fmt.Errorf("crio ImageHistory failed.%v", err)
	}
	var result []container.HistoryResponseItem
	for _, his := range imageInfo.ImageSpec.History {
		result = append(result, container.HistoryResponseItem{
			Comment:   his.Comment,
			Created:   his.Created.Unix(),
			CreatedBy: his.CreatedBy,
			// ID:        "",
			// Size:      0,
			// Tags:      nil,
		})
	}
	return result, nil
}

func (c *crioDriver) RuntimeInfo() (container.RuntimeInfo, error) {
	runtimeInfo := container.RuntimeInfo{
		RuntimeType:  version,
		RootDir:      "/var/lib/containers/storage",
		Driver:       "overlaycrio",
		DriverStatus: nil,
	}
	return runtimeInfo, nil
}

// GetImageLayersDir crio  每层layer路径
func (c *crioDriver) GetImageLayersDir(namespace, imageId string) (layerDirs []string, isTmpDir bool, err error) {
	info, err := c.imageClient.ImageFsInfo()
	if err != nil {
		return nil, isTmpDir, fmt.Errorf("ImageFsInfo failed. %v", err)
	}
	if len(info) == 0 {
		return nil, isTmpDir, fmt.Errorf("crio ImageFsInfo failed")
	}
	var imagePath string
	if info[0].GetFsId() != nil {
		imagePath = info[0].GetFsId().GetMountpoint()
	}
	_, err = os.Stat(global.MountPathInContainer)
	if err == nil {
		imagePath = filepath.Join(global.MountPathInContainer, imagePath)
	}
	// get real imageId
	var realImageId string
	imageStatus, err := c.imageClient.ImageStatus(&runtimeapi.ImageSpec{
		Image: imageId,
	}, false)
	if err != nil || imageStatus == nil || imageStatus.Image == nil {
		logging.Get().Err(err).Msgf("crio GetImageLayersDir ImageStatus failed.Image:%s", imageId)
	} else {
		realImageId = imageStatus.Image.Id
	}

	// get  first diffId
	encodeConfigName := fmt.Sprintf("=%s", base64.StdEncoding.EncodeToString([]byte("sha256:"+realImageId)))
	finalPath := filepath.Join(imagePath, realImageId, encodeConfigName)
	bytes, err := os.ReadFile(finalPath)
	if err != nil {
		logging.Get().Err(err).Msg("ReadFile failed.")
		return nil, isTmpDir, fmt.Errorf("ReadFile failed. %v", err)
	}
	var image CRIOImage
	err = json.Unmarshal(bytes, &image)
	if err != nil {
		return nil, isTmpDir, fmt.Errorf("Unmarshal CRIOImage failed.%v", err)
	}
	if len(image.Rootfs.DiffIds) == 0 {
		return nil, isTmpDir, fmt.Errorf("diffId is empty. realImageId:%s", realImageId)
	}
	firstDiffId := strings.TrimPrefix(image.Rootfs.DiffIds[0], "sha256:")
	// get layers
	parentDir := filepath.Dir(imagePath)
	overlayPath := filepath.Join(parentDir, "overlay")              // 镜像的文件信息
	overlayLayersPath := filepath.Join(parentDir, "overlay-layers") // layer 层级关系

	var layerList []LayerItem
	layerBytes, err := os.ReadFile(filepath.Join(overlayLayersPath, "/layers.json"))
	if err != nil {
		return nil, isTmpDir, fmt.Errorf("ReadFile layers.json failed.%v", err)
	}
	err = json.Unmarshal(layerBytes, &layerList)
	if err != nil {
		return nil, isTmpDir, fmt.Errorf("unmarshal LayerItem failed.%v", err)
	}
	layerMap := make(map[string]string) // parentId :id
	for _, item := range layerList {
		if item.Parent == "" {
			continue
		}
		layerMap[item.Parent] = item.Id
	}
	var resultPath []string
	parentId := firstDiffId
	resultPath = append(resultPath, filepath.Join(overlayPath, parentId, "/diff"))
	for {
		p, ok := layerMap[parentId]
		if !ok {
			break
		}
		parentId = p
		resultPath = append(resultPath, filepath.Join(overlayPath, p, "/diff"))
	}
	return resultPath, isTmpDir, nil
}

// TODO fix
func (c *crioDriver) SaveImage(namespace, imageID, fullPath string) (string, error) {
	// TODO implement me
	return "", fmt.Errorf("获取镜像目录请调用GetImageLayersDir")
}

func (c *crioDriver) clearContainerTimeoutData() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for now := range ticker.C {
		func(nowTime time.Time) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()

			c.Lock()
			defer c.Unlock()

			if c.deleteCount >= 60 { // if a map keeps a stable size but is with continuous add or delete, it should be reconstructed after a period of time to prevent memory leak
				newMap := make(map[string]int64, len(c.runningContainerMap))
				for containerID, timestamp := range c.runningContainerMap {
					if nowTime.Unix()-timestamp >= containerIDTimeoutSec {
						continue
					}
					newMap[containerID] = timestamp
				}
				c.runningContainerMap = newMap
				c.deleteCount = 0
			}
		}(now)
	}
}

type CRIOImage struct {
	Architecture string `json:"architecture"`
	Config       struct {
		Env    []string `json:"Env"`
		Cmd    []string `json:"Cmd"`
		Labels struct {
			OrgOpencontainersImageRefName string `json:"org.opencontainers.image.ref.name"`
			OrgOpencontainersImageVersion string `json:"org.opencontainers.image.version"`
		} `json:"Labels"`
		ArgsEscaped bool        `json:"ArgsEscaped"`
		OnBuild     interface{} `json:"OnBuild"`
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
		Type    string   `json:"type"`
		DiffIds []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type LayerItem struct {
	Id                   string    `json:"id"`
	Parent               string    `json:"parent"`
	Created              time.Time `json:"created"`
	CompressedDiffDigest string    `json:"compressed-diff-digest"`
	CompressedSize       int       `json:"compressed-size"`
	DiffDigest           string    `json:"diff-digest"`
	DiffSize             int       `json:"diff-size"`
	Compression          int       `json:"compression"`
	Uidset               []int     `json:"uidset"`
	Gidset               []int     `json:"gidset"`
}

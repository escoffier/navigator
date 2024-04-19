package learn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"

	"gitlab.com/piccolo_su/vegeta/pkg/fanotify"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/mq"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/utils/strings/slices"
)

const (
	inModelFileKeyTemplate = "%s_%s" // path, containerName
	inModelCmdKeyTemplate  = "%s_%s" // command, containerName
)

var (
	gFileWls           []fileWhitelist
	gCmdWls            []cmdWhitelist
	gFileWlsLock       sync.RWMutex
	gCmdWlsLock        sync.RWMutex
	gIgnoreKnownAttack bool
)

type clusterContainerInfo struct {
	PodUID             string
	ContainerID        string
	ContainerName      string
	Pid                int
	PodName            string
	Namespace          string
	ResourceKind       string
	ResourceName       string
	ContainerLabelName string
}

type learningStatus struct {
	status int // 1. learning 3. enabled
}

type FileResourceCtrl struct {
	Hostname          string
	ClusterKey        string
	ClusterName       string
	PodName           string
	Namespace         string
	ResourceKind      string
	ResourceName      string
	PodUID            string
	ContainerFileCtrl map[string]*fanotify.FileAccessCtrl
	ResourceID        uint32
	ExistPath         *sync.Map
	ExistCmd          *sync.Map
	InModelPath       *sync.Map
	InModelCmd        *sync.Map
	PidCommandMap     *sync.Map
	status            learningStatus
	alerter           *Alert
}

type LearningHandler struct {
	clusterMgr            *k8s.ClusterInfoManager
	npw                   *nodeinfo.NodePodsWatcher
	pri                   *nodeinfo.PodResInfo
	mq                    mq.Writer
	excludeNamespace      []string
	rt                    container.Runtime
	alerter               *Alert // for sending msg to event center
	LearningConfigMapLock sync.Locker
	faHandler             map[uint32]*FileResourceCtrl
	learningResourcesMap  map[uint32]learningStatus
	clusterKey            string
	clusterName           string
	Hostname              string
}

type fileWhitelist struct {
	Path       string `json:"path"`
	Permission int    `json:"permission"`
	FileName   string `json:"file_name"`
}

type cmdWhitelist struct {
	Command string `json:"command"`
	User    string `json:"user"`
	Path    string `json:"path"`
}

func NewLearningHandler(clusterMgr *k8s.ClusterInfoManager, mq mq.Writer, npw *nodeinfo.NodePodsWatcher, pri *nodeinfo.PodResInfo) (*LearningHandler, error) {

	lh := &LearningHandler{
		clusterMgr:            clusterMgr,
		npw:                   npw,
		pri:                   pri,
		mq:                    mq,
		LearningConfigMapLock: new(sync.Mutex),
		learningResourcesMap:  make(map[uint32]learningStatus),
	}
	// lh.pathMap = make(map[string]struct{})
	lh.faHandler = make(map[uint32]*FileResourceCtrl)
	// exclude namespace
	lh.excludeNamespace = global.GetExcludeNamespaces()

	// runtime interface
	rt, err := container.CreateRuntimeCli()
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to create runtime interface")
		return nil, err
	}
	lh.rt = rt

	// static cluster info
	clusterKey, ok := lh.clusterMgr.ClusterKey()
	if !ok {
		logging.GetLogger().Err(err).Msg("failed to get cluster key")
		return nil, fmt.Errorf("failed to get cluster key")
	}
	lh.clusterKey = clusterKey
	clusterName, ok := lh.clusterMgr.ClusterName()
	if !ok {
		logging.GetLogger().Err(err).Msg("failed to get cluster name")
		return nil, fmt.Errorf("failed to get cluster name")
	}
	lh.clusterName = clusterName

	lh.Hostname = npw.NodeName

	a, err := NewAlert()
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to create alert")
		return nil, err
	}
	lh.alerter = a

	return lh, nil
}

func (lh *LearningHandler) StartLearning() error {
	logging.GetLogger().Info().Msg("start learning")
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("panic: %v", r)
			}
		}()
		err := lh.listenConfigMap(context.Background())
		if err != nil {
			logging.GetLogger().Error().Msgf("listenConfigMap: %v", err)
		}

	}()

	wg.Wait()
	return nil
}

func (lh *LearningHandler) updateFromConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error {
	logging.GetLogger().Info().Msgf("update config map, name %v", configMap.Name)

	lh.LearningConfigMapLock.Lock()
	defer lh.LearningConfigMapLock.Unlock()

	if configMap.Name == model.BehavioralLearnConfigMapName {
		logging.GetLogger().Info().Msgf("configmap name: %s", configMap.Name)
		resourcesLearning := make(map[uint32]learningStatus)
		if len(configMap.Data) == 0 {
			logging.GetLogger().Info().Msg("configmap data is empty")
			lh.cleanWater()
			return nil
		}
		for k, v := range configMap.Data {
			var err error
			var resourceUUID uint32
			var endTime int64
			var op int
			keyList := strings.Split(k, "-")
			valueList := strings.Split(v, model.BehavioralLearnConfigMapValueDelimiter)
			logging.GetLogger().Info().Msgf("keyList: %v, valueList: %v", keyList, valueList)

			endTimeStr := valueList[len(valueList)-1]
			endTime, err = strconv.ParseInt(endTimeStr, 10, 64)
			if err != nil {
				logging.GetLogger().Warn().Msgf("parse configmap value error, value: %s", v)
				continue
			}

			opStr := valueList[len(valueList)-3]
			op, err = strconv.Atoi(opStr)
			if err != nil {
				logging.GetLogger().Warn().Msgf("parse configmap value error, value: %s", v)
				continue
			}

			resourceUUIDStr := keyList[len(keyList)-1]

			uuid, err := strconv.ParseUint(resourceUUIDStr, 10, 32)
			if err != nil {
				logging.GetLogger().Warn().Msgf("parse configmap key error, key: %s", k)
				continue
			}
			resourceUUID = uint32(uuid)

			if err != nil {
				logging.GetLogger().Warn().Msgf("parse configmap value error, value: %s", v)
				continue
			}
			if endTime != 0 && endTime < time.Now().Unix() {
				continue
			}
			resourcesLearning[resourceUUID] = learningStatus{
				status: op,
			}

			logging.GetLogger().Info().Msgf("resourceUUID: %d, endTime: %d, op: %d", resourceUUID, endTime, op)
		}
		go lh.UpdateWatcherResource(resourcesLearning)

	} else if configMap.Name == model.BehavioralLearnWhitelistName {
		updateGlobalWhitelist(configMap.Data)
	} else if strings.HasPrefix(configMap.Name,
		model.BehavioralLearnModelConfigMapNameTemplate[:len(model.BehavioralLearnModelConfigMapNameTemplate)-3]) {
		logging.GetLogger().Info().Msgf("configmap name: %s", configMap.Name)
		uuidStr := strings.Split(configMap.Name, "-")[2]
		uuid, err := strconv.ParseUint(uuidStr, 10, 32)
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse configmap name error, name: %s", configMap.Name)
			return nil
		}
		lh.UpdateResourceModel(uint32(uuid), configMap.Data)
	} else if configMap.Name == model.BehavioralLearnGlobalConfigMapName {
		logging.GetLogger().Info().Msgf("configmap name: %s", configMap.Name)
		for k, v := range configMap.Data {
			if k == "global" {
				values := strings.Split(v, ":")
				if len(values) != 4 {
					logging.GetLogger().Warn().Msgf("parse configmap value error, value: %s", v)
					continue
				}
				IgnoreKnownAttackStr := values[0]
				if IgnoreKnownAttackStr == "true" {
					gIgnoreKnownAttack = true
				} else {
					gIgnoreKnownAttack = false
				}
			}
		}
	} else {
		logging.GetLogger().Info().Msgf("configmap name: %s", configMap.Name)

	}

	return nil
}

func updateGlobalWhitelist(cmData map[string]string) {
	gFileWlsLock.Lock()
	defer gFileWlsLock.Unlock()
	gCmdWlsLock.Lock()
	defer gCmdWlsLock.Unlock()
	logging.GetLogger().Info().Msgf("update global whitelist cmData: %v", cmData)
	gFileWls = []fileWhitelist{}
	gCmdWls = []cmdWhitelist{}
	for k, v := range cmData {
		if strings.HasPrefix(k, model.BehavioralLearnFileModelKeyTemplate[:len(model.BehavioralLearnFileModelKeyTemplate)-3]) {
			strList := strings.Split(v, ":")
			if len(strList) != len(strings.Split(model.BehavioralLearnFileModelWlsValueTemplate, ":")) {
				logging.GetLogger().Error().Msgf("parse configmap value error, value: %s", v)
				continue
			}
			path := strList[0]
			permissionStr := strList[1]
			permission, err := strconv.Atoi(permissionStr)
			if err != nil {
				logging.GetLogger().Error().Msgf("parse permission error, permission: %s", v)
				continue
			}
			fwls := fileWhitelist{
				Path:       path,
				Permission: permission,
				FileName:   filepath.Base(path),
			}
			gFileWls = append(gFileWls, fwls)
		} else if strings.HasPrefix(k, model.BehavioralLearnCommandModelKeyTemplate[:len(model.BehavioralLearnCommandModelKeyTemplate)-3]) {
			strList := strings.Split(v, ":")
			if len(strList) != len(strings.Split(model.BehavioralLearnCommandModelWlsValueTemplate, ":")) {
				logging.GetLogger().Error().Msgf("parse configmap value error, value: %s", v)
				continue
			}
			path := strList[0]
			command := strList[1]
			user := strList[2]
			cmdWls := cmdWhitelist{
				Path:    path,
				Command: command,
				User:    user,
			}
			gCmdWls = append(gCmdWls, cmdWls)
		}
	}
}

func compareGlobalFileWhitelist(path string, permission int) bool {
	gFileWlsLock.RLock()
	defer gFileWlsLock.RUnlock()
	// regexp match
	for _, v := range gFileWls {
		if v.Permission == permission {
			match, err := regexp.MatchString(v.Path, path)
			if err != nil {
				logging.GetLogger().Error().Msgf("regexp match error, pattern: %s, path: %s", v.FileName, path)
			}
			if match {
				return true
			}

		}
	}
	return false
}

func compareGlobalCommandWhitelist(command string, user string, path string) bool {
	gCmdWlsLock.RLock()
	defer gCmdWlsLock.RUnlock()
	for _, v := range gCmdWls {
		if v.User == user {
			match, err := regexp.MatchString(v.Command, command)
			// logging.GetLogger().Debug().Msgf("command: %s, regexp: %s, match: %t", command, v.Command, match)
			if err != nil {
				logging.GetLogger().Error().Msgf("regexp match error, pattern: %s, command: %s", v.Command, command)
			}
			if !match {
				continue
			}
			match2, err := regexp.MatchString(v.Path, path)
			// logging.GetLogger().Debug().Msgf("path: %s, regexp: %s, match: %t", path, v.Path, match2)
			if err != nil {
				logging.GetLogger().Error().Msgf("regexp match error, pattern: %s, path: %s", v.Path, path)
			}
			if match && match2 {
				return true
			}
		}
	}
	return false
}

func eraseSyncMap(m *sync.Map) {
	m.Range(func(key, value interface{}) bool {
		logging.GetLogger().Debug().Msgf("delete key: %s", key)
		m.Delete(key)
		return true
	})
}

// func loopSyncMap(m *sync.Map) {
// 	m.Range(func(key, value interface{}) bool {
// 		logging.GetLogger().Debug().Msgf("loop sync map key: %s, value: %v", key, value)
// 		return true
// 	})
// }

func (lh *LearningHandler) UpdateResourceModel(resourceUUID uint32, cmData map[string]string) {
	logging.GetLogger().Info().Msgf("update resource model, uuid: %d, data: %v", resourceUUID, cmData)
	if _, ok := lh.faHandler[resourceUUID]; ok {
		handler := lh.faHandler[resourceUUID]
		eraseSyncMap(handler.InModelPath)
		eraseSyncMap(handler.InModelCmd)
		eraseSyncMap(handler.ExistPath)
		eraseSyncMap(handler.ExistCmd)
		for k, v := range cmData {
			if strings.HasPrefix(k, model.BehavioralLearnFileModelKeyTemplate[:len(model.BehavioralLearnFileModelKeyTemplate)-3]) {
				strList := strings.Split(v, ":")
				logging.GetLogger().Debug().Msgf("strList: %v", strList)
				path := strList[0]
				permissionStr := strList[1]
				permission, err := strconv.Atoi(permissionStr)
				if err != nil {
					logging.GetLogger().Error().Msgf("parse permission error, permission: %s", v)
					continue
				}
				containerName := strList[2]
				handler.InModelPath.Store(fmt.Sprintf(inModelFileKeyTemplate, path, containerName), permission)

				// data, ok := handler.ExistPath.Load(path + containerName)
				// logging.GetLogger().Debug().Msgf("data: %v, ok: %t", data, ok)
			} else if strings.HasPrefix(k, model.BehavioralLearnCommandModelKeyTemplate[:len(model.BehavioralLearnCommandModelKeyTemplate)-3]) {
				strList := strings.Split(v, ":")
				logging.GetLogger().Debug().Msgf("strList: %v", strList)
				command := strList[0]
				user := strList[1]
				containerName := strList[2]
				handler.InModelCmd.Store(fmt.Sprintf(inModelCmdKeyTemplate, command, containerName), user)
				// data, ok := handler.InModelCmd.Load(command + containerName)
				// logging.GetLogger().Debug().Msgf("data: %v, ok: %t", data, ok)
			}
		}
	} else {
		logging.GetLogger().Info().Msgf("container %d not in watch list", resourceUUID)
	}

}

func (lh *LearningHandler) UpdateWatcherResource(resources map[uint32]learningStatus) error {
	logging.GetLogger().Info().Msg("update watcher resource")
	// lh.learningResourcesMap = resources
	existResources := lh.learningResourcesMap

	containers, err := lh.rt.ListRunningContainers()
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to list all containers")
		return err
	}
	for _, v := range containers {
		logging.GetLogger().Debug().Msgf("container: %s/%s", v.Namespace, v.Names)
		meta, err := lh.rt.GetContainerMeta(v.Namespace, v.ID)
		if err != nil {
			logging.GetLogger().Err(err).Interface("container", v.Names).Msg("failed to get container meta")
			continue
		}
		if lh.shouldExcludeWatch(meta) {
			logging.GetLogger().Warn().Msgf("container %s/%s is excluded", meta.Namespace, meta.Name)
			continue
		}

		if len(meta.PodUID) == 0 {
			logging.GetLogger().Warn().Msgf("container %s/%s podUID is empty", meta.Namespace, meta.Name)
			continue
		}
		cci := &clusterContainerInfo{
			ContainerID:        v.ID,
			ContainerName:      meta.Name,
			Pid:                meta.ProcessID,
			ContainerLabelName: meta.Labels["io.kubernetes.container.name"],
		}
		err = lh.fillK8sPodInfo(meta.PodUID, cci)
		if err != nil {
			logging.GetLogger().Err(err).Msg("failed to fill k8s pod info")
			continue
		}
		if slices.Contains(lh.excludeNamespace, cci.Namespace) {
			logging.GetLogger().Info().Msgf("container %s/%s in exclude namespace", meta.Namespace, meta.Name)
			continue
		}
		logging.GetLogger().Info().Msgf("container %s/%s is not in exclude namespace", meta.Namespace, meta.Name)
		uuid := util.GenerateUUID(lh.clusterKey, cci.Namespace, cci.ResourceKind, cci.ResourceName)
		if v, ok := resources[uuid]; ok {
			logging.GetLogger().Info().Msgf("container %s/%s is learning", meta.Namespace, meta.Name)
			delete(existResources, uuid)
			err = lh.addContainerWatch(cci, uuid, v.status)
			if err != nil {
				logging.GetLogger().Err(err).Msg("failed to add container watch")
				continue
			}

		}
	}

	for k, _ := range existResources {
		logging.GetLogger().Info().Msgf("container %d is not learning", k)
		err = lh.removeContainerWatch(k)
		if err != nil {
			logging.GetLogger().Err(err).Msg("failed to remove container watch")
			continue
		}
	}
	lh.learningResourcesMap = resources

	return nil
}

func (lh *LearningHandler) removeContainerWatch(resourceUUID uint32) error {
	logging.GetLogger().Info().Msgf("remove container watch, uuid: %d", resourceUUID)
	if _, ok := lh.faHandler[resourceUUID]; ok {
		handler := lh.faHandler[resourceUUID]
		for _, v := range handler.ContainerFileCtrl {
			v.MonitorExit()
		}
		delete(lh.faHandler, resourceUUID)
		return nil
	} else {
		logging.GetLogger().Info().Msgf("container %d not in watch list", resourceUUID)
	}
	return nil
}

func (lh *LearningHandler) UpdateModelsOnEnabled(resourceID uint32) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}
	configmapKey := fmt.Sprintf(model.BehavioralLearnModelConfigMapNameTemplate, resourceID)
	configMap, err := lh.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Get(context.Background(), configmapKey, metav1.GetOptions{})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get configmap %s error", configmapKey)
		return err
	}
	logging.GetLogger().Info().Msgf("configmap %s data: %v", configmapKey, configMap.Data)
	lh.UpdateResourceModel(resourceID, configMap.Data)
	return nil
}

func (lh *LearningHandler) addContainerWatch(cci *clusterContainerInfo, uuid uint32, status int) error {
	logging.GetLogger().Info().Msgf("add container watch, uuid: %d", uuid)
	if _, ok := lh.faHandler[uuid]; ok {
		handler := lh.faHandler[uuid]
		handler.status.status = status
		if _, ok := handler.ContainerFileCtrl[cci.ContainerID]; ok {
			logging.GetLogger().Info().Msgf("container %s/%s already in watch list", cci.Namespace, cci.ResourceName)
			return nil
		}
		fa, ok := fanotify.NewFileAccessCtrl(true)
		if !ok {
			logging.GetLogger().Error().Msg("failed to create fanotify file access control")
			return errors.New("failed to create fanotify file access control")
		}
		fa.AddDirMarks(cci.Pid, []string{"/"})
		handler.ContainerFileCtrl[cci.ContainerID] = fa
		go handler.monitorFilePermissionEvents(fa, lh.mq, cci)
		lh.UpdateModelsOnEnabled(uuid)
	} else {
		fa, ok := fanotify.NewFileAccessCtrl(true)
		if !ok {
			logging.GetLogger().Error().Msg("failed to create fanotify file access control")
			return errors.New("failed to create fanotify file access control")
		}
		fa.AddDirMarks(cci.Pid, []string{"/"})
		cfc := make(map[string]*fanotify.FileAccessCtrl)
		cfc[cci.ContainerID] = fa
		frc := &FileResourceCtrl{
			ClusterKey:        lh.clusterKey,
			ClusterName:       lh.clusterName,
			PodName:           cci.PodName,
			Namespace:         cci.Namespace,
			ResourceKind:      cci.ResourceKind,
			ResourceName:      cci.ResourceName,
			Hostname:          lh.Hostname,
			PodUID:            cci.PodUID,
			ContainerFileCtrl: cfc,
			ResourceID:        uuid,
			ExistPath:         new(sync.Map),
			ExistCmd:          new(sync.Map),
			InModelPath:       new(sync.Map),
			InModelCmd:        new(sync.Map),
			PidCommandMap:     new(sync.Map),
			alerter:           lh.alerter,
		}
		frc.status.status = status
		go frc.monitorFilePermissionEvents(fa, lh.mq, cci)
		logging.GetLogger().Debug().Msgf("add container watch, uuid: %d", uuid)
		lh.faHandler[uuid] = frc
		lh.UpdateModelsOnEnabled(uuid)
	}
	return nil
}

func (lh *LearningHandler) listenConfigMap(ctx context.Context) error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	outTime := time.Minute * 20
	timer := time.NewTimer(outTime)

	watcher, err := lh.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
		LabelSelector: model.BehaviorConfigMapLabel,
	})
	if err != nil {
		return err
	}

	logging.GetLogger().Info().Msgf("start listening configmap %s", model.BehaviorConfigMapLabel)

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				logging.GetLogger().Warn().Msg("watcher.ResultChan() closed")
				watcher.Stop()
				watcher, err = lh.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
					LabelSelector: model.BehaviorConfigMapLabel,
				})
				if err != nil {
					logging.GetLogger().Error().Msgf("watch configmap error: %v", err)
				}
				timer.Reset(outTime)
				continue
			}
			switch event.Type {
			case watch.Added:
				configMap := event.Object.(*corev1.ConfigMap)
				logging.GetLogger().Info().Msgf("ConfigMap added: %v\n", configMap.Data)
				err = lh.updateFromConfigMap(ctx, configMap)
				if err != nil {
					logging.GetLogger().Error().Msgf("updateFromConfigMap error: %v", err)
				}
			case watch.Modified:
				configMap := event.Object.(*corev1.ConfigMap)
				logging.GetLogger().Info().Msgf("ConfigMap modified: %v\n", configMap.Data)
				err = lh.updateFromConfigMap(ctx, configMap)
				if err != nil {
					logging.GetLogger().Error().Msgf("updateFromConfigMap error: %v", err)
				}
			case watch.Deleted:
				configMap := event.Object.(*corev1.ConfigMap)
				logging.GetLogger().Info().Msgf("ConfigMap deleted: %v\n", configMap.Data)
				err = lh.updateFromConfigMap(ctx, configMap)
				if err != nil {
					logging.GetLogger().Error().Msgf("updateFromConfigMap error: %v", err)
				}
			case watch.Error:
				logging.GetLogger().Info().Msgf("configmap error: %v", event.Object)
			}
		case <-timer.C:
			logging.GetLogger().Info().Msgf("timeout: %v", outTime)
			watcher.Stop()
			watcher, err = lh.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
				LabelSelector: model.BehaviorConfigMapLabel,
			})
			if err != nil {
				logging.GetLogger().Error().Msgf("watch configmap error: %v", err)
			}
		}
	}

	return nil
}

func (frc *FileResourceCtrl) monitorFilePermissionEvents(fa *fanotify.FileAccessCtrl, mq mq.Writer, cci *clusterContainerInfo) error {
	waitCnt := 0
	pfd := make([]unix.PollFd, 1)
	pfd[0].Fd = fa.Fanfd.GetFd()
	pfd[0].Events = unix.POLLIN
	logging.GetLogger().Debug().Interface("pfd", pfd[0]).Msg("FA: start")
	for fa.Enabled {
		n, err := unix.Poll(pfd, 5000)       // wait 5 sec
		if err != nil && err != unix.EINTR { // not interrupted by a signal
			logging.GetLogger().Error().Msgf("FA: poll returns error: %v", err)
			break
		}

		if n <= 0 {
			if n == 0 && !fa.Enabled { // timeout at exit stage
				waitCnt += 1
				if waitCnt > 1 { // two chances
					break
				}
			}
			continue
		}
		if (pfd[0].Revents & unix.POLLIN) != 0 {
			frc.handleEvents(fa, mq, cci)
			waitCnt = 0
		}
	}

	fa.MonitorExit()
	logging.GetLogger().Info().Msg("FA: exit")
	return errors.New("FA: exit")
}

func filterSelfByProcessName(processName string) bool {
	return processName == "daemon" || processName == ""

}

func isSameProcess(p processInfo, pMap *sync.Map) bool {
	logging.GetLogger().Debug().Msgf("isSameProcess: process: %+v", p)
	pid := p.ProcessID
	if pid <= 0 {
		logging.GetLogger().Debug().Msgf("isSameProcess: pid: %d <= 0", pid)
		return false
	}
	cmdLine2, ok := pMap.LoadOrStore(p.ProcessID, p.CMD)
	if !ok {
		logging.GetLogger().Debug().Msgf("isSameProcess: pid: %d not in pMap", p.ProcessID)
		return false
	}
	logging.GetLogger().Debug().Msgf("isSameProcess: pid: %d cmd: %s cmdLine2: %v", p.ProcessID, p.CMD, cmdLine2)
	if value, ok := cmdLine2.(string); ok && value == p.CMD {
		logging.GetLogger().Debug().Msgf("isSameProcess: pid: %d cmd: %s equal to pid2: %v", p.ProcessID, p.CMD, cmdLine2)
		return true
	}

	pMap.Store(p.ProcessID, p.CMD)
	return false
}

func (frc *FileResourceCtrl) handleEvents(fa *fanotify.FileAccessCtrl, mq mq.Writer, cci *clusterContainerInfo) error {
	for fa.Enabled {
		ev, err := fa.Fanfd.GetEvent()
		if err != nil {
			logging.GetLogger().Error().Msgf("handleEvents: get event error: %v", err)
			return err
		}
		go func() {
			defer func() {
				err = ev.File.Close()
				if err != nil {
					// log.Err(err).Msg("ev file close err.")
					logging.GetLogger().Err(err).Msgf("handleEvents: ev file close")
				}
			}()

			// print some info
			evPid := ev.Pid
			// evProcessName, err := fanotify.EventProcessName(ev, fa.RunInContainer)
			// if err != nil {
			// 	logging.GetLogger().Error().Msgf("handleEvents: get process name error: %v", err)
			// }
			// evPPID := fanotify.EventPPID(ev, fa.RunInContainer)

			curProcessInfo := getProcessFromPID(int(evPid), fa.RunInContainer)
			// ppInfo := getProcessFromPID(evPPID, fa.RunInContainer)
			// logging.GetLogger().Debug().Msgf("handleEvents: process info curProcessInfo: %v, ppInfo: %v", curProcessInfo, ppInfo)
			logging.GetLogger().Debug().Msgf("handleEvents: process info curProcessInfo: %v", curProcessInfo)

			if filterSelfByProcessName(curProcessInfo.ProcessName) {
				logging.GetLogger().Debug().Msgf("handleEvents: ignore self process: %s", curProcessInfo.ProcessName)
				goto releaseFile
			}
			{
				//evFileName := ev.File.Name()// filename is nil for fa.fanfd.GetEvent assign nil file name
				evFilePath, _ := fanotify.EventFilePath(ev, fa.RunInContainer)

				evType := fanotify.EventType(ev)

				timestamp := time.Now().Unix()

				// log.Debug().
				logging.GetLogger().Debug().
					Int32("pid", evPid).
					Interface("fd", ev.File.Fd()).
					Str("processName", curProcessInfo.ProcessName).
					// Str("fileName", evFileName).
					Str("filePath", evFilePath).
					Str("evType", evType).
					Msg("handleEvents: event info")

				ignoreAttackFileAccess := false
				if frc.status.status == model.BehavioralLearningStatusRunning && gIgnoreKnownAttack {
					if strings.Contains(filepath.Base(evFilePath), "nmap") || strings.Contains(filepath.Base(evFilePath), "nc") || strings.Contains(filepath.Base(evFilePath), "ncat") || strings.Contains(filepath.Base(evFilePath), "hydra") {
						logging.GetLogger().Debug().Msgf("handleEvents: ignore known attack: %s", evFilePath)
						ignoreAttackFileAccess = true
					}
				}

				// evType FAN_OPEN: read
				// evType FAN_CLOSE_WRITE: write
				permission := 0
				if ev.MatchMask(fanotify.FAN_OPEN) && !ev.MatchMask(fanotify.FAN_CLOSE_WRITE) {
					permission = 1
				} else {
					permission = 2
				}

				// loopSyncMap(frc.InModelPath)
				_, isExistPath := frc.ExistPath.LoadOrStore(evFilePath, struct{}{})
				permissionStr, isInModelPath := frc.InModelPath.Load(fmt.Sprintf(inModelFileKeyTemplate, evFilePath, cci.ContainerLabelName))
				if isInModelPath {
					permissionInt := 0
					if value, ok := permissionStr.(int); ok {
						permissionInt = value
					} else {
						logging.GetLogger().Debug().Msgf("handleEvents: permissionStr: %v type: %v", permissionStr, reflect.TypeOf(permissionStr))
					}

					if permission != permissionInt {
						isInModelPath = false
					}
				}
				if !isInModelPath && !ignoreAttackFileAccess {
					if ev.Version != fanotify.FANOTIFY_METADATA_VERSION {
						logging.GetLogger().Debug().Msg("handleEvents: not match version,do nothing")
						return
					}

					fileEvent := model.BehavioralKafkaEvent{
						ResourceUUID:   frc.ResourceID,
						EventType:      model.BehavioralLearnKafkaFileEvent,
						Path:           evFilePath,
						FilePath:       evFilePath,
						Permission:     permission,
						Name:           filepath.Base(evFilePath),
						LearningStatus: frc.status.status,
						CreatedAt:      timestamp,
						ContainerID:    cci.ContainerID,
						ContainerName:  cci.ContainerLabelName,
					}
					matchGlobalWls := compareGlobalFileWhitelist(evFilePath, permission)
					if !matchGlobalWls && !isExistPath {
						msg, err := json.Marshal(fileEvent)
						if err != nil {
							logging.GetLogger().Error().Msgf("handleEvents: json marshal err: %v", err)
							return
						}

						err = Send2Kafka(mq, model.SubjectOfBehavioralLearnEvent, msg)
						if err != nil {
							logging.GetLogger().Error().Msgf("handleEvents: send to kafka err: %v", err)
							return
						}
					}

					// send to sherlock
					if !matchGlobalWls {
						var permissionStr string
						if permission == 1 {
							permissionStr = "read"
						} else {
							permissionStr = "write/read"
						}
						if frc.status.status == model.BehavioralLearningStatusEnabled {
							eventArg := &FileEventArg{
								ClusterID:     frc.ClusterKey,
								Cluster:       frc.ClusterName,
								Hostname:      frc.Hostname,
								PodName:       frc.PodName,
								Namespace:     frc.Namespace,
								PodUID:        frc.PodUID,
								ResourceKind:  frc.ResourceKind,
								ResourceName:  frc.ResourceName,
								ContainerID:   cci.ContainerID,
								ContainerName: cci.ContainerLabelName,
								FilePath:      evFilePath,
								Permission:    permissionStr,
							}
							ruleKey, scopes, signalContext := frc.alerter.genFilePalaceSignalParams(eventArg, AlertCategory, FileAlertRuleName)
							go frc.alerter.Send(ruleKey, scopes, signalContext)

						}
					}
				}

				ignoreAttackCommand := false
				if frc.status.status == model.BehavioralLearningStatusRunning && gIgnoreKnownAttack {
					if strings.Contains(curProcessInfo.CMD, "nmap ") || strings.Contains(curProcessInfo.CMD, "nc ") || strings.Contains(curProcessInfo.CMD, "ncat ") || strings.Contains(curProcessInfo.CMD, "hydra ") {
						logging.GetLogger().Info().Msgf("handleEvents: ignore known attack: %s", curProcessInfo.CMD)
						ignoreAttackCommand = true
					}
				}
				// _, isExistCmd := frc.ExistCmd.LoadOrStore(ppInfo.CMD, struct{}{})
				// _, isInModelCmd := frc.InModelCmd.Load(fmt.Sprintf(inModelCmdKeyTemplate, ppInfo.CMD, cci.ContainerLabelName))

				// if !isInModelCmd && !ignoreAttackCommand && !isSameProcess(ppInfo, frc.PidCommandMap) &&
				// 	ppInfo.ProcessID != 0 && ppInfo.CMD != "" && !strings.HasSuffix(curProcessInfo.ProcessName, "sh") {
				// 	commandEvent := model.BehavioralKafkaEvent{
				// 		ResourceUUID:   frc.ResourceID,
				// 		EventType:      model.BehavioralLearnKafkaCommandEvent,
				// 		Path:           ppInfo.Path,
				// 		Command:        ppInfo.CMD,
				// 		LearningStatus: frc.status.status,
				// 		User:           ppInfo.User,
				// 		ContainerID:    cci.ContainerID,
				// 		ContainerName:  cci.ContainerLabelName,
				// 		CreatedAt:      timestamp,
				// 	}
				// 	matchGlobalWls := compareGlobalCommandWhitelist(ppInfo.CMD, ppInfo.User, ppInfo.Path)
				// 	if !matchGlobalWls && !isExistCmd {
				// 		msg, err := json.Marshal(commandEvent)
				// 		if err != nil {
				// 			logging.GetLogger().Error().Msgf("handleEvents: json marshal err: %v", err)
				// 			return
				// 		}

				// 		err = Send2Kafka(mq, model.SubjectOfBehavioralLearnEvent, msg)
				// 		if err != nil {
				// 			logging.GetLogger().Error().Msgf("handleEvents: send to kafka err: %v", err)
				// 			return
				// 		}
				// 	}

				// 	if !matchGlobalWls {
				// 		if frc.status.status == model.BehavioralLearningStatusEnabled {
				// 			eventArg := &CmdEventArg{
				// 				ClusterID:     frc.ClusterKey,
				// 				Cluster:       frc.ClusterName,
				// 				Hostname:      frc.Hostname,
				// 				PodName:       frc.PodName,
				// 				Namespace:     frc.Namespace,
				// 				PodUID:        frc.PodUID,
				// 				ResourceKind:  frc.ResourceKind,
				// 				ResourceName:  frc.ResourceName,
				// 				ContainerID:   cci.ContainerID,
				// 				ContainerName: cci.ContainerLabelName,
				// 				Cmd:           ppInfo.CMD,
				// 				Path:          ppInfo.Path,
				// 				User:          ppInfo.User,
				// 			}
				// 			ruleKey, scopes, signalContext := frc.alerter.genCmdPalaceSignalParams(eventArg, AlertCategory, CmdAlertRuleName)
				// 			go frc.alerter.Send(ruleKey, scopes, signalContext)
				// 		}
				// 	}

				// }

				ignoreAttackCommand = false
				if frc.status.status == model.BehavioralLearningStatusRunning && gIgnoreKnownAttack {
					if strings.Contains(curProcessInfo.CMD, "nmap ") || strings.Contains(curProcessInfo.CMD, "nc ") || strings.Contains(curProcessInfo.CMD, "ncat ") || strings.Contains(curProcessInfo.CMD, "hydra ") {
						logging.GetLogger().Info().Msgf("handleEvents: ignore known attack: %s", curProcessInfo.CMD)
						ignoreAttackCommand = true
					}
				}

				_, isExistCmd := frc.ExistCmd.LoadOrStore(curProcessInfo.CMD, struct{}{})
				_, isInModelCmd := frc.InModelCmd.Load(fmt.Sprintf(inModelCmdKeyTemplate, curProcessInfo.CMD, cci.ContainerLabelName))
				if !isInModelCmd && !ignoreAttackCommand && !isSameProcess(curProcessInfo, frc.PidCommandMap) &&
					curProcessInfo.ProcessID != 0 && curProcessInfo.CMD != "" {
					commandEvent := model.BehavioralKafkaEvent{
						ResourceUUID:   frc.ResourceID,
						EventType:      model.BehavioralLearnKafkaCommandEvent,
						Path:           curProcessInfo.Path,
						Command:        curProcessInfo.CMD,
						LearningStatus: frc.status.status,
						User:           curProcessInfo.User,
						ContainerID:    cci.ContainerID,
						ContainerName:  cci.ContainerLabelName,
						CreatedAt:      timestamp,
					}
					matchGlobalWls := compareGlobalCommandWhitelist(curProcessInfo.CMD, curProcessInfo.User, curProcessInfo.Path)
					if !matchGlobalWls && !isExistCmd {
						msg, err := json.Marshal(commandEvent)
						if err != nil {
							logging.GetLogger().Error().Msgf("handleEvents: json marshal err: %v", err)

						}

						err = Send2Kafka(mq, model.SubjectOfBehavioralLearnEvent, msg)
						if err != nil {
							logging.GetLogger().Error().Msgf("handleEvents: send to kafka err: %v", err)

						}
					}

					if !matchGlobalWls {
						if frc.status.status == model.BehavioralLearningStatusEnabled {
							eventArg := &CmdEventArg{
								ClusterID:     frc.ClusterKey,
								Cluster:       frc.ClusterName,
								Hostname:      frc.Hostname,
								PodName:       frc.PodName,
								Namespace:     frc.Namespace,
								PodUID:        frc.PodUID,
								ResourceKind:  frc.ResourceKind,
								ResourceName:  frc.ResourceName,
								ContainerID:   cci.ContainerID,
								ContainerName: cci.ContainerLabelName,
								Cmd:           curProcessInfo.CMD,
								Path:          curProcessInfo.Path,
								User:          curProcessInfo.User,
							}
							ruleKey, scopes, signalContext := frc.alerter.genCmdPalaceSignalParams(eventArg, AlertCategory, CmdAlertRuleName)
							go frc.alerter.Send(ruleKey, scopes, signalContext)
						}
					}

				}
			}
		releaseFile:
			if ev.MatchMask(fanotify.FAN_OPEN_PERM) || ev.MatchMask(fanotify.FAN_OPEN_EXEC_PERM) || ev.MatchMask(fanotify.FAN_ACCESS_PERM) {
				err = fa.Fanfd.Response(ev, true)
				if err != nil {
					logging.GetLogger().Err(err).Msg("handleEvents: response allow err")
				} else {
					logging.GetLogger().Debug().Msg("handleEvents: response allow ok")
				}
			} else {
				logging.GetLogger().Debug().Msg("handleEvents: not match perm events,do nothing")
			}

		}()
	}

	return nil
}

func (rs *LearningHandler) shouldExcludeWatch(meta container.ContainerMeta) bool {
	return slices.Contains(rs.excludeNamespace, meta.PodNamespace())
}

func (lh *LearningHandler) cleanWater() {
	logging.GetLogger().Info().Msg("clean water")
	for _, v := range lh.faHandler {
		for _, v1 := range v.ContainerFileCtrl {
			v1.MonitorExit()
		}
	}
	lh.faHandler = make(map[uint32]*FileResourceCtrl)
}

func (lh *LearningHandler) fillK8sPodInfo(podID string, cci *clusterContainerInfo) error {
	// pod info
	logging.GetLogger().Info().Msgf("podID: %s", podID)
	cci.PodUID = podID
	// k8s pod info
	podInfo, err := lh.npw.GetPodByUID(podID)
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to get pod info")
		return err
	}
	cci.PodName = podInfo.Name
	cci.Namespace = podInfo.Namespace
	logging.GetLogger().Info().Msgf("podInfo: %+v", podInfo)
	// k8s resource info
	resource, ok := lh.pri.GetPod(podInfo.Namespace, podInfo.Name)
	if !ok {
		logging.GetLogger().Error().Str("podName", podInfo.Name).Msg("failed to get pod resource")
		return fmt.Errorf("failed to get pod resource")
	}
	cci.ResourceKind = resource.Kind
	cci.ResourceName = resource.Name

	logging.GetLogger().Info().Msgf("resource: %+v", resource)
	return nil
}

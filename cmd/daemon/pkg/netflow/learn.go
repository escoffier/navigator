package netflow

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	pkgModel "gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	AlertCategory        = "ImmuneDefense"
	NetworkAlertRuleName = "Network access exceptions in containers"
)

type Alert struct {
	palaceHandler *palace.Palace
}

type ActionTable struct {
	Status                int
	SendToBehavioralLearn bool
	SendToAlert           bool
}

type NetworkArg struct {
	ClusterID       string
	Cluster         string
	ResourceKind    string
	ResourceName    string
	Hostname        string
	Namespace       string
	PodName         string
	PodUID          string
	ContainerID     string
	ContainerName   string
	Port            int
	StreamDirection string
	ProcessName     string
	SrcResource     string
}
type networkModelInfo struct {
	ClusterKey      string
	Kind            string
	Name            string
	Namespace       string
	Port            int
	StreamDirection int
}

type learningStatus struct {
	status        int // 1. learning 3. enabled
	InModel       map[uint32]struct{}
	ReportAlready map[uint32]struct{}
}

type networkWhiteList struct {
	ClusterKey      string
	Kind            string
	Name            string
	Namespace       string
	Port            int
	StreamDirection int
}

type Learn struct {
	clusterMgr        *k8s.ClusterInfoManager
	ListenResource    map[uint32]learningStatus
	ConfigMapLock     sync.Mutex
	Wls               []networkWhiteList
	Alert             *Alert
	IgnoreKnownAttack bool
}

func NewLearn(clusterManager *k8s.ClusterInfoManager,
) *Learn {
	l := &Learn{
		clusterMgr: clusterManager,
	}
	l.ListenResource = make(map[uint32]learningStatus)
	l.Alert, _ = NewAlert()
	return l

}

func (l *Learn) updateFromConfigMap(ctx context.Context, configMap *corev1.ConfigMap) error {
	l.ConfigMapLock.Lock()
	defer l.ConfigMapLock.Unlock()
	if configMap.Name == model.BehavioralLearnConfigMapName {
		resourcesLearning := make(map[uint32]learningStatus)
		if len(configMap.Data) == 0 {
			logging.GetLogger().Info().Msg("configmap data is empty")
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
				status:        op,
				ReportAlready: make(map[uint32]struct{}),
			}

			logging.GetLogger().Info().Msgf("resourceUUID: %d, endTime: %d, op: %d", resourceUUID, endTime, op)
		}
		l.UpdateResourceStatus(resourcesLearning)
	} else if configMap.Name == model.BehavioralLearnWhitelistName {
		l.UpdateWhitelist(configMap.Data)
	} else if strings.HasPrefix(configMap.Name,
		model.BehavioralLearnModelConfigMapNameTemplate[:len(model.BehavioralLearnModelConfigMapNameTemplate)-3]) {
		logging.GetLogger().Debug().Msgf("configmap name: %s", configMap.Name)
		uuidStr := strings.Split(configMap.Name, "-")[2]
		uuid, err := strconv.ParseUint(uuidStr, 10, 32)
		if err != nil {
			logging.GetLogger().Warn().Msgf("parse configmap name error, name: %s", configMap.Name)
			return nil
		}
		l.UpdateResourceModel(uint32(uuid), configMap.Data)
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
					l.IgnoreKnownAttack = true
				} else {
					l.IgnoreKnownAttack = false
				}
			}
		}
	} else {
		logging.GetLogger().Info().Msgf("configmap name: %s", configMap.Name)

	}

	return nil
}

func (l *Learn) UpdateWhitelist(cmData map[string]string) {
	for k, v := range cmData {
		if strings.HasPrefix(k, model.BehavioralLearnNetworkModelKeyTemplate[:len(model.BehavioralLearnNetworkModelKeyTemplate)-3]) {
			values := strings.Split(v, ":")
			if len(values) != len(strings.Split(model.BehavioralLearnNetworkModelWlsValueTemplate, ":")) {
				logging.GetLogger().Warn().Msgf("parse whitelist error, value: %s", v)
				continue
			}
			port, err := strconv.Atoi(values[4])
			if err != nil {
				logging.GetLogger().Warn().Msgf("parse whitelist error, value: %s", v)
				continue
			}
			streamDirection, err := strconv.Atoi(values[5])
			if err != nil {
				logging.GetLogger().Warn().Msgf("parse whitelist error, value: %s", v)
				continue
			}

			l.Wls = append(l.Wls, networkWhiteList{
				ClusterKey:      values[0],
				Kind:            values[1],
				Namespace:       values[2],
				Name:            values[3],
				Port:            port,
				StreamDirection: streamDirection,
			})
		}
	}
}

func (l *Learn) UpdateResourceModel(uuid uint32, cmData map[string]string) {
	learnStatus := l.ListenResource[uuid]
	inModelMap := make(map[uint32]struct{})

	for k, v := range cmData {
		if strings.HasPrefix(k, model.BehavioralLearnNetworkModelKeyTemplate[:len(model.BehavioralLearnNetworkModelKeyTemplate)-3]) {
			values := strings.Split(v, ":")
			if len(values) != len(strings.Split(model.BehavioralLearnNetworkModelValueTemplate, ":")) {
				logging.GetLogger().Warn().Msgf("parse error, value: %s", v)
				continue
			}
			modelUUID := util.GenerateUUID(values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7])
			inModelMap[modelUUID] = struct{}{}
		}
	}
	if learnStatus.ReportAlready != nil {
		for k, _ := range learnStatus.InModel {
			if _, ok := inModelMap[k]; !ok {
				delete(learnStatus.ReportAlready, k)
			}
		}
	} else {
		learnStatus.ReportAlready = make(map[uint32]struct{})
	}
	logging.GetLogger().Debug().Msgf("inModelMap: %+v", inModelMap)
	learnStatus.InModel = inModelMap
	l.ListenResource[uuid] = learnStatus

	logging.GetLogger().Debug().Msgf("update resource model: %+v", l.ListenResource)
}

func (l *Learn) UpdateResourceStatus(resourceMap map[uint32]learningStatus) {
	updateMap := make(map[uint32]learningStatus)
	for k, v := range resourceMap {
		if tmpStatus, ok := l.ListenResource[k]; !ok {
			updateMap[k] = v
		} else {
			tmpStatus.status = v.status
			updateMap[k] = tmpStatus
		}
	}
	l.ListenResource = updateMap
	logging.GetLogger().Info().Msgf("update resource status: %+v", l.ListenResource)
}

func (l *Learn) ListenConfigMap(ctx context.Context) error {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	outTime := time.Minute * 20
	timer := time.NewTimer(outTime)

	watcher, err := l.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
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
				watcher, err = l.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
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
				logging.GetLogger().Debug().Msgf("ConfigMap added: %v\n", configMap.Data)
				err = l.updateFromConfigMap(ctx, configMap)
				if err != nil {
					logging.GetLogger().Error().Msgf("updateFromConfigMap error: %v", err)
				}
			case watch.Modified:
				configMap := event.Object.(*corev1.ConfigMap)
				logging.GetLogger().Info().Msgf("ConfigMap modified: %v\n", configMap.Data)
				err = l.updateFromConfigMap(ctx, configMap)
				if err != nil {
					logging.GetLogger().Error().Msgf("updateFromConfigMap error: %v", err)
				}
			case watch.Deleted:
				configMap := event.Object.(*corev1.ConfigMap)
				logging.GetLogger().Info().Msgf("ConfigMap deleted: %v\n", configMap.Data)
				err = l.updateFromConfigMap(ctx, configMap)
				if err != nil {
					logging.GetLogger().Error().Msgf("updateFromConfigMap error: %v", err)
				}
			case watch.Error:
				logging.GetLogger().Info().Msgf("configmap error: %v", event.Object)
			}
		case <-timer.C:
			logging.GetLogger().Info().Msgf("timeout: %v", outTime)
			watcher.Stop()
			watcher, err = l.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
				LabelSelector: model.BehaviorConfigMapLabel,
			})
			if err != nil {
				logging.GetLogger().Error().Msgf("watch configmap error: %v", err)
			}
		}
	}

	return nil

}

func (l *Learn) compareGlobalNetworkWhitelist(networkFlow pkgModel.TensorNetworkFlow, streamDirection int) bool {
	for _, wl := range l.Wls {
		if wl.ClusterKey == networkFlow.DstCluster && wl.Kind == networkFlow.DstKind &&
			wl.Namespace == networkFlow.DstNamespace && wl.Name == networkFlow.DstOwnerName &&
			wl.Port == int(networkFlow.DstPort) && wl.StreamDirection == streamDirection {
			return true
		}
	}
	return false
}

func (l *Learn) filterIgnoreKnownAttack(networkFlow pkgModel.TensorNetworkFlow) bool {

	if l.IgnoreKnownAttack {
		processName := networkFlow.DstProcess
		if strings.Contains(processName, "nc") || strings.Contains(processName, "hydra") || strings.Contains(processName, "nmap") {
			return true
		}
	}
	return false
}

func (l *Learn) NeedSendToBehavioralLearn(uuid uint32, networkFlow pkgModel.TensorNetworkFlow, streamDir int) ActionTable {
	l.ConfigMapLock.Lock()
	defer l.ConfigMapLock.Unlock()
	learnStatus, ok := l.ListenResource[uuid]
	if !ok {
		logging.GetLogger().Debug().Msgf("uuid: %d not in learning status", uuid)
		return ActionTable{
			Status:                0,
			SendToBehavioralLearn: false,
			SendToAlert:           false,
		}
	}
	logging.GetLogger().Info().Msgf("learnStatus: %+v", learnStatus)
	if learnStatus.status != 3 && learnStatus.status != 1 {
		return ActionTable{
			Status:                learnStatus.status,
			SendToBehavioralLearn: false,
			SendToAlert:           false,
		}
	}

	modelUUIDWithoutProcessName := util.GenerateUUID(networkFlow.SrcCluster, networkFlow.SrcKind, networkFlow.SrcNamespace, networkFlow.SrcOwnerName, strconv.Itoa(int(networkFlow.DstPort)), strconv.Itoa(streamDir), networkFlow.SrcContainerName, "")

	modelUUID := util.GenerateUUID(networkFlow.SrcCluster, networkFlow.SrcKind, networkFlow.SrcNamespace, networkFlow.SrcOwnerName, strconv.Itoa(int(networkFlow.DstPort)), strconv.Itoa(streamDir), networkFlow.SrcContainerName, networkFlow.SrcProcess)
	logging.GetLogger().Debug().Msgf("modelUUID: %d", modelUUID)
	if learnStatus.status == model.BehavioralLearningStatusRunning && l.filterIgnoreKnownAttack(networkFlow) {
		logging.GetLogger().Debug().Msgf("ignore known attack")
		return ActionTable{
			Status:                learnStatus.status,
			SendToBehavioralLearn: false,
			SendToAlert:           false,
		}
	}
	_, ok = learnStatus.InModel[modelUUID]
	if ok {
		logging.GetLogger().Debug().Msgf("modelUUID: %d in model", modelUUID)
		return ActionTable{
			Status:                learnStatus.status,
			SendToBehavioralLearn: false,
			SendToAlert:           false,
		}
	} else if _, ok := learnStatus.InModel[modelUUIDWithoutProcessName]; ok {
		logging.GetLogger().Debug().Msgf("modelUUID: %d in model", modelUUIDWithoutProcessName)
		return ActionTable{
			Status:                learnStatus.status,
			SendToBehavioralLearn: false,
			SendToAlert:           false,
		}
	}

	if l.compareGlobalNetworkWhitelist(networkFlow, streamDir) {
		logging.GetLogger().Debug().Msgf("model:%s/%s/%s(%s) in global whitelist", networkFlow.SrcCluster, networkFlow.SrcNamespace, networkFlow.SrcOwnerName, networkFlow.SrcKind)
		return ActionTable{
			Status:                learnStatus.status,
			SendToBehavioralLearn: false,
			SendToAlert:           false,
		}
	}

	if learnStatus.ReportAlready == nil {
		learnStatus.ReportAlready = make(map[uint32]struct{})
	}

	if _, ok := learnStatus.ReportAlready[modelUUID]; ok {
		logging.GetLogger().Debug().Msgf("modelUUID: %d already report", modelUUID)
		return ActionTable{
			Status:                learnStatus.status,
			SendToBehavioralLearn: false,
			SendToAlert:           true,
		}
	}
	learnStatus.ReportAlready[modelUUID] = struct{}{}
	if learnStatus.status == model.BehavioralLearningStatusRunning {
		logging.GetLogger().Debug().Msgf("modelUUID: %d send to behavioral learn", modelUUID)
		return ActionTable{
			Status:                learnStatus.status,
			SendToBehavioralLearn: true,
			SendToAlert:           false,
		}
	}
	logging.GetLogger().Debug().Msgf("modelUUID: %d send to alert", modelUUID)
	return ActionTable{
		Status:                learnStatus.status,
		SendToBehavioralLearn: true,
		SendToAlert:           true,
	}
}

func (a *Alert) genPalaceSignalParams(arg *NetworkArg, category, name model.AlertKind) (palace.RuleKey, []palace.Scope, map[string]interface{}) {
	ruleKey := palace.RuleKey{
		Version1: 2,
		Category: string(category),
		Name:     string(name),
	}

	// kind,name must have value
	scopes := []palace.Scope{
		{
			Kind: palace.ScopeKindContainer,
			ID:   arg.ContainerID,   // container id
			Name: arg.ContainerName, // container name
		},
		{
			Kind: palace.ScopeKindPod,
			ID:   arg.PodUID,  // pod id
			Name: arg.PodName, // pod name
		},
		{
			Kind: palace.ScopeKindNamespace,
			Name: arg.Namespace, // namespace name
		},
		{
			Kind: palace.ScopeKindHostname,
			Name: arg.Hostname,
		},
		{
			Kind: palace.ScopeKindCluster,
			ID:   arg.ClusterID,
			Name: arg.Cluster, // cluster name
		},
		{
			Kind: palace.ScopeKindResource,
			Name: fmt.Sprintf("%s(%s)", arg.ResourceName, arg.ResourceKind),
		},
		{
			Kind: palace.ScopeKindScene,
			ID:   palace.ScopeIDSceneK8s,
			Name: palace.ScopeNameSceneK8s,
		},
	}

	// event params
	params := map[string]interface{}{
		"port":             arg.Port,
		"resource_name":    arg.SrcResource,
		"stream_direction": arg.StreamDirection,
		"process_name":     arg.ProcessName,
	}

	return ruleKey, scopes, params
}

func (a *Alert) Send(arg *NetworkArg) error {

	ruleKey, scopes, params := a.genPalaceSignalParams(arg, AlertCategory, NetworkAlertRuleName)

	err := a.palaceHandler.SendSignal(ruleKey, scopes, params)
	if err != nil {
		logging.GetLogger().Err(err).Msg("send signal failed")
	}
	return err
}

func NewAlert() (*Alert, error) {
	a := &Alert{}
	palaceHandler, err := palace.Init()
	if err != nil {
		return nil, err
	}
	a.palaceHandler = &palaceHandler
	return a, nil
}

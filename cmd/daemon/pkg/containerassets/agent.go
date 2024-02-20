package containerassets

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"k8s.io/apimachinery/pkg/util/wait"
)

type Agent struct {
	mqWriter mq.Writer
	cache    *cache
	lock     sync.Mutex
	mqReady  atomic.Bool
}

func NewAgent(writer mq.Writer) *Agent {
	return &Agent{mqWriter: writer, cache: newCache(1000)}
}

// HandlerContainerEvent 调用方：运行时事件;k8s事件
func (a *Agent) HandlerContainerEvent(ctx context.Context, clusterKey string, action assets.Action, container *assets.TensorRawContainer) {
	logging.Get().Info().Msgf("raw-container -HandlerContainerEvent: action:%d,containerId:%s,name:%s,resourceName:%s",
		int(action), container.ContainerID, container.Name, container.ResourceName)
	if !a.mqReady.Load() { // 此处会导致启动时，k8s监听的pod add事件不会存入缓存。
		logging.Get().Error().Str("raw-container", "handle event").Msg("mq is not ready")
		return
	}
	finalContainer := container
	if container.K8sManaged && (container.ResourceName == "" || container.ContainerID == "") {
		if action == assets.ActionUpdate {
			if container.ContainerID == "" { //pod更新事件忽略
				return
			}
		} else if action == assets.ActionAdd {
			// 这段逻辑意义不大，start的容器事件中，已经将容器的resourceName，resourceKind收集到了，不会进入内部；
			// 前面a.mqReady.Load()的异常就被绕过。 因为 容器start事件不会进入内部 一直等待k8s方的owner数据
			logging.Get().Info().Msgf("raw-container 1 action:%d,containerId:%s", int(action), container.ContainerID)
			rawContainer, ok := a.cache.get(keyFunc(container.Namespace, container.PodName))
			if !ok {
				logging.Get().Info().Msgf("raw-container 2 cache container")
				err := a.cache.add(container.Namespace, container.PodName, *container)
				if err != nil {
					logging.Get().Err(err).Msgf("raw-container - add cache err %s", container.ContainerID)
					return
				}
				return
			}
			logging.Get().Info().Msgf("raw-container 3 id:%s,resourceName:%s,", container.ContainerID, rawContainer.ResourceName)
			logging.Get().Info().Msgf("raw-container 3 id:%s,resourceName:%s,", rawContainer.ContainerID, container.ResourceName)

			if container.ContainerID != "" && rawContainer.ResourceName != "" {
				// container from docker runtime
				finalContainer = container
				finalContainer.ResourceName = rawContainer.ResourceName
				finalContainer.ResourceKind = rawContainer.ResourceKind
				finalContainer.VolumeMounts = utils.MergeVolumeMounts(rawContainer.VolumeMounts, container.VolumeMounts)
				finalContainer.Ports = utils.MergeContainerPorts(rawContainer.Ports, container.Ports, rawContainer.IP)
				a.cache.remove(container.Namespace, container.PodName)
			} else if container.ResourceName != "" && rawContainer.ContainerID != "" {
				// container from k8s informer
				finalContainer = &rawContainer
				finalContainer.ResourceName = container.ResourceName
				finalContainer.ResourceKind = container.ResourceKind
				finalContainer.VolumeMounts = utils.MergeVolumeMounts(container.VolumeMounts, rawContainer.VolumeMounts)
				finalContainer.Ports = utils.MergeContainerPorts(container.Ports, rawContainer.Ports, container.IP)
				a.cache.remove(container.Namespace, container.PodName)
			} else {
				logging.Get().Info().Msgf("raw-container - incomplete container (%s/%s)-(%s)", finalContainer.Namespace, finalContainer.ResourceName, finalContainer.Name)
				return
			}
		}
	}

	event := &assets.ResourceEvent{
		Action:     action,
		Type:       assets.RawContainer,
		ClusterKey: clusterKey,
		Resource:   finalContainer,
	}
	data, err := json.Marshal(event)
	if err != nil {
		logging.Get().Err(err).Msgf("marshal container: %s failed", container.ContainerID)
		return
	}

	logging.Get().Info().Msgf("raw-container - send message. id:%s,action:%d,name:%s,podName:%s,status:%d,statusDesc:%s",
		finalContainer.ContainerID, int(action), finalContainer.Name, finalContainer.PodName, finalContainer.Status, finalContainer.StatusDesc)
	err = a.mqWriter.Write(ctx, "kube-resources", kafka.Message{
		Key:   []byte(container.ContainerID),
		Value: data,
	})
	if err != nil {
		logging.Get().Err(err).Msgf("failed to write raw-container: %s to mq", container.ContainerID)
		return
	}
}

func (a *Agent) HandlerContainerSync(ctx context.Context, clusterKey, nodeName string, t time.Time) {
	event := &assets.ResourceEvent{
		Type:       assets.ContainerSync,
		ClusterKey: clusterKey,
		Resource: &assets.TensorSync{
			Cluster:  clusterKey,
			NodeName: nodeName,
			SyncTime: t,
		},
	}
	data, err := json.Marshal(event)
	if err != nil {
		logging.Get().Err(err).Msg("marshal container sync failed")
		return
	}

	logging.Get().Info().Msgf("handle container sync: %v", string(data))
	err = a.mqWriter.Write(ctx, "kube-resources", kafka.Message{
		Key:   []byte(clusterKey),
		Value: data,
	})
	if err != nil {
		logging.Get().Err(err).Msg("failed to write raw-container sync to mq")
		return
	}
}

// HandlerContainerSyncCheck check if syncing container could start, it will wait until check passed
func (a *Agent) HandlerContainerSyncCheck(ctx context.Context, clusterKey, nodeName string) {
	event := &assets.ResourceEvent{
		Type:       assets.ContainerSyncStart,
		ClusterKey: clusterKey,
		Resource: &assets.TensorSync{
			Cluster:  clusterKey,
			NodeName: nodeName,
			SyncTime: time.Now(),
		},
	}
	data, err := json.Marshal(event)
	if err != nil {
		logging.Get().Err(err).Str("raw-container", "sync start").Msgf("marshal container sync-start: %s failed")
		return
	}

	logging.Get().Debug().Str("raw-container", "sync start").Msg("handle container sync start")
	stopChan := make(chan struct{})
	wait.PollImmediateUntil(time.Second*10, func() (done bool, err error) {
		err = a.mqWriter.Write(ctx, "kube-resources", kafka.Message{
			Key:   []byte(clusterKey),
			Value: data,
		})
		if err != nil {
			logging.Get().Err(err).Str("raw-container", "sync start").Msg("failed to write raw-container sync-start to mq")
			return false, nil
		}
		return true, nil
	}, stopChan)

}

func (a *Agent) MqReady(flag bool) {
	a.mqReady.Store(flag)
}

package containerassets

import (
	"context"
	"encoding/json"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"k8s.io/apimachinery/pkg/util/wait"
	"sync"
	"sync/atomic"
	"time"
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
func (a *Agent) HandlerContainerEvent(ctx context.Context, clusterKey string, action assets.Action, container *model.TensorRawContainer) {
	if !a.mqReady.Load() {
		logging.Get().Debug().Str("raw-container", "handle event").Msg("mq is not ready")
		return
	}
	finalContainer := container
	if container.K8sManaged && action != assets.ActionDelete && (container.ResourceName == "" || container.ContainerID == "") {
		rawContainer, ok := a.cache.get(keyFunc(container.Namespace, container.PodName))
		if !ok {
			logging.Get().Debug().Msgf("raw-container - cache container: %+v", container)
			err := a.cache.add(container.Namespace, container.PodName, *container)
			if err != nil {
				logging.Get().Warn().Err(err).Msgf("raw-container - add cache err %s", container.ContainerID)
				return
			}
			return
		}

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
			logging.Get().Debug().Msgf("raw-container - incomplete container %+v", finalContainer)
			return
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

	logging.Get().Debug().Msgf("raw-container - handle container: %v", string(data))
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
		logging.Get().Err(err).Msgf("marshal container sync: %s failed")
		return
	}

	logging.Get().Debug().Msgf("handle container sync: %v", string(data))
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

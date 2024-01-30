package assets

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
)

type PodContainerWatcher struct {
	rdb *databases.RDBInstance
}

type PodContainerCallBack struct {
	parent     *PodContainerWatcher
	consumed   int32
	inputQueue *util.Queue
}

func (cb *PodContainerCallBack) OnSync(*assets.TensorSync) error {
	return nil
}

func (cb *PodContainerCallBack) OnRawContainer(*assets.TensorRawContainer, assets.Action) error {
	return nil
}

func newPodContainerWatcher(rdb *databases.RDBInstance) *PodContainerWatcher {
	return &PodContainerWatcher{
		rdb: rdb,
	}
}

func (p *PodContainerWatcher) BeforeWatchNewCluster(context.Context, string, time.Duration) assets.ClusterCallback {
	ccb := &PodContainerCallBack{
		parent:     p,
		inputQueue: util.NewQueue(),
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
			}
		}()

		consumed := ccb.tryToConsumePods()
		if consumed {
			logging.Get().Info().Msg("start to consume pods")
		}
	}()
	return ccb
}

func (p *PodContainerWatcher) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch: {},
	}
}

func (p *PodContainerWatcher) Name() string {
	return "PodContainerWatcher"
}

func (cb *PodContainerCallBack) OnTensorResourceEvent(*assets.TensorResource, *assets.TensorResource, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) AfterDataSynced(_ context.Context, dataSynced bool, clusterKey string) {
	if dataSynced {
		cb.inputQueue.Add(syncSignal{clusterKey: clusterKey})
	}
}

func (cb *PodContainerCallBack) OnTensorPod(pod *assets.TensorPod, action assets.Action) error {
	cb.inputQueue.Add(podEvent{
		pod:        pod,
		action:     action,
		updateTime: time.Now(),
	})
	return nil
}

func (cb *PodContainerCallBack) OnTensorRole(*assets.TensorRole, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnTensorClusterRole(*assets.TensorClusterRole, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnTensorIngress(*assets.TensorIngress, assets.Action) error {
	// TODO implement me
	return nil
}

func (cb *PodContainerCallBack) OnTensorService(*assets.TensorService, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnTensorEndpoints(*assets.TensorEndpoints, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnTensorSecret(*assets.TensorSecret, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnTensorPV(*assets.TensorPV, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnTensorPVC(*assets.TensorPVC, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnTensorNamespace(*assets.TensorNamespace, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnTensorNode(*assets.TensorNode, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) OnHoneyspot(*assets.TensorHoneySpot, assets.Action) error {
	return nil
}

func (cb *PodContainerCallBack) Name() string {
	return "PodContainerCallBack"
}

func (cb *PodContainerCallBack) tryToConsumePods() bool {
	toConsume := atomic.CompareAndSwapInt32(&cb.consumed, 0, 1)
	if toConsume {
		cb.inputQueue.Consume(func(item interface{}) {
			switch typed := item.(type) {
			case syncSignal:
				s := item.(syncSignal)
				err := cb.removeInactiveData(context.Background(), s.clusterKey)
				if err != nil {
					logging.Get().Err(err).Msg("do removeInactiveData error")
				} else {
					logging.Get().Info().Msg("cluster information scyned")
				}
			case podEvent:
				err := cb.doOnPodEvent(context.Background(), typed)
				if err != nil {
					logging.Get().Err(err).Msgf("do on pod event %+v error", typed)
				}
			}
		})
		return true
	}
	return false
}

func (cb *PodContainerCallBack) doOnPodEvent(ctx context.Context, e podEvent) (err error) {
	defer func() {
		if r := recover(); r != nil {
			podName := ""
			if e.pod != nil {
				podName = fmt.Sprintf("%s/%s", e.pod.Namespace, e.pod.Name)
			}
			logging.Get().Error().Msgf("Panic when do on pod (%s) event: %v. event: %+v", podName, r, e)
			err = errors.New("panic")
		}
	}()

	tctx, cancel := context.WithTimeout(ctx, 8000*time.Millisecond)
	defer cancel()

	switch e.action {
	case assets.ActionDelete:
		rerr := dal.DeletePodContainerRelation(tctx, cb.parent.rdb.Get(), e.pod.Cluster, e.pod.Namespace, e.pod.Name)
		if rerr != nil {
			logging.Get().Err(rerr).Msg("delete pod container rel in rdb error")
		}
	case assets.ActionUpdate, assets.ActionAdd:
		rerr := dal.UpsertPodContainerRelation(tctx, cb.parent.rdb.Get(), e.pod.Pod, e.pod.Owner.Name, e.pod.Owner.Kind, e.pod.Cluster, e.updateTime, e.pod.PoolInfo)
		if rerr != nil {
			logging.Get().Err(rerr).Msg("upsert pod container rel in rdb error")
		}
	}
	return nil
}

func (cb *PodContainerCallBack) removeInactiveData(ctx context.Context, clusterKey string) error {
	return dal.CleanUpPodContainerRelations(ctx, cb.parent.rdb.Get(), time.Now(), clusterKey)
}

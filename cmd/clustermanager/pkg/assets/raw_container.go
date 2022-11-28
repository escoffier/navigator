package assets

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	"time"
)

var _ assets.Callback = (*RawContainerWatcher)(nil)
var _ assets.ClusterCallback = (*RawContainerCallBack)(nil)

type RawContainerWatcher struct {
	rdb *databases.RDBInstance
}

type containerEvent struct {
	container  *assets.TensorRawContainer
	action     assets.Action
	updateTime time.Time
}

func newRawContainerWatcher(rdb *databases.RDBInstance) *RawContainerWatcher {
	return &RawContainerWatcher{
		rdb: rdb,
	}
}

func (r *RawContainerWatcher) BeforeWatchNewCluster(context.Context, string, time.Duration) assets.ClusterCallback {
	ccb := &RawContainerCallBack{
		parent: r,
	}
	return ccb
}

func (r *RawContainerWatcher) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.RawContainer: {},
	}
}

func (r *RawContainerWatcher) Name() string {
	return "RawContainerWatcher"
}

type RawContainerCallBack struct {
	parent     *RawContainerWatcher
	consumed   int32
	inputQueue *util.Queue
}

func (cb *RawContainerCallBack) OnRawContainer(container *assets.TensorRawContainer, action assets.Action) error {
	return cb.doOnRawContainerEvent(context.Background(), containerEvent{
		container:  container,
		action:     action,
		updateTime: time.Now(),
	})
}

func (cb *RawContainerCallBack) doOnRawContainerEvent(ctx context.Context, e containerEvent) (err error) {
	defer func() {
		if r := recover(); r != nil {
			containerName := ""
			if e.container != nil {
				containerName = fmt.Sprintf("%s/%s", e.container.Namespace, e.container.Name)
			}
			logging.Get().Error().Msgf("Panic when do on pod (%s) event: %v. event: %+v", containerName, r, e)
			err = errors.New("panic")
		}
	}()

	tctx, cancel := context.WithTimeout(ctx, 8000*time.Millisecond)
	defer cancel()

	switch e.action {
	case assets.ActionDelete:
		rerr := dal.DeleteRawContainer(tctx, cb.parent.rdb.Get(), e.container.ClusterKey, e.container.ContainerID)
		if rerr != nil {
			logging.Get().Err(rerr).Msg("delete raw container rel in rdb error")
		}
	case assets.ActionUpdate, assets.ActionAdd:
		rerr := dal.UpsertRawContainers(tctx, cb.parent.rdb.Get(), (*model.TensorRawContainer)(e.container))
		if rerr != nil {
			logging.Get().Err(rerr).Msg("upsert raw container rel in rdb error")
		}
	}
	return nil
}

func (cb *RawContainerCallBack) removeInactiveData(ctx context.Context, sync *assets.TensorSync) error {
	logging.Get().Info().Msgf("remove Inactive container: %+v", sync)
	return dal.CleanUpRawContainer(ctx, cb.parent.rdb.Get(), sync.SyncTime, sync.Cluster, sync.NodeName)
}

func (cb *RawContainerCallBack) OnTensorResourceEvent(*assets.TensorResource, *assets.TensorResource, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnNodeEvent(*corev1.Node, *corev1.Node, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) AfterDataSynced(_ context.Context, _ bool, _ string) {
}

func (cb *RawContainerCallBack) OnTensorPod(*assets.TensorPod, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorRole(*assets.TensorRole, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorClusterRole(*assets.TensorClusterRole, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorNamespace(*assets.TensorNamespace, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorNode(*assets.TensorNode, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnHoneyspot(*assets.TensorHoneySpot, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnSync(sync *assets.TensorSync) error {
	err := cb.removeInactiveData(context.Background(), sync)
	if err != nil {
		logging.Get().Err(err).Msg("do removeInactiveData error")
	} else {
		logging.Get().Info().Msg("cluster information scyned")
	}
	return err
}

func (cb *RawContainerCallBack) Name() string {
	return "RawContainerCallBack"
}

package assets

import (
	"context"
	"errors"
	"fmt"
	"time"

	rs "github.com/March-deng/godisearch/redisearch"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/redisearch"
)

var _ assets.Callback = (*RawContainerWatcher)(nil)
var _ assets.ClusterCallback = (*RawContainerCallBack)(nil)

type RawContainerWatcher struct {
	rdb *databases.RDBInstance
	// redisearch clients
	redisearchClis *redisearch.Client
}

type containerEvent struct {
	container  *assets.TensorRawContainer
	action     assets.Action
	updateTime time.Time
}

func newRawContainerWatcher(rdb *databases.RDBInstance, redisearchClis *redisearch.Client) *RawContainerWatcher {
	return &RawContainerWatcher{
		rdb:            rdb,
		redisearchClis: redisearchClis,
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

// call enableRedisSearch before mustGetRedisSearchClient
func (rl *RawContainerWatcher) mustGetRedisSearchClient(modelType string) *rs.Client {
	c, err := rl.redisearchClis.GetIndexClient(modelType)
	if err != nil {
		panic(err)
	}

	return c
}

func (rl *RawContainerWatcher) enableRedisSearch(modelType string) bool {
	if rl.redisearchClis != nil {
		c, err := rl.redisearchClis.GetIndexClient(modelType)
		if err != nil {
			return false
		}
		return c != nil
	}
	return false
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

	useRedis := cb.parent.enableRedisSearch("rawContainer")

	logging.Get().Info().Msgf("process raw container event, action: %d, container: %s,name: %s, resource: %s/%s, useRedis: %t", e.action, e.container.ContainerID, e.container.Name, e.container.ResourceKind, e.container.ResourceName, useRedis)

	switch e.action {
	case assets.ActionDelete:
		var deleteErr error
		if useRedis {
			deleteErr = dal.DeleteRawContainerWithRedis(tctx, cb.parent.rdb.Get(), cb.parent.mustGetRedisSearchClient("rawContainer"), e.container.ClusterKey, e.container.ContainerID)
		} else {
			deleteErr = dal.DeleteRawContainer(tctx, cb.parent.rdb.Get(), e.container.ClusterKey, e.container.ContainerID)
		}
		if deleteErr != nil {
			logging.Get().Err(deleteErr).Msg("delete raw container rel in rdb error,containerId:" + e.container.ContainerID)
		}
		deleteErr = dal.DeleteRawContainerSyncReason(tctx, cb.parent.rdb.Get(), e.container.ClusterKey, e.container.Namespace, e.container.ContainerID)
		if deleteErr != nil {
			logging.Get().Err(deleteErr).Msgf("delete raw container sync reason in rdb error.%s,%s,%s", e.container.ContainerID)
		}

	case assets.ActionUpdate, assets.ActionAdd:

		var upsertErr error
		if useRedis {
			upsertErr = dal.UpsertRawContainerWithRedis(tctx, cb.parent.rdb.Get(), cb.parent.mustGetRedisSearchClient("rawContainer"), e.container)
		} else {
			upsertErr = dal.UpsertRawContainers(tctx, cb.parent.rdb.Get(), e.container)
		}

		if upsertErr != nil {
			logging.Get().Err(upsertErr).Msg("upsert raw container rel in rdb error,containerId:" + e.container.ContainerID)
		}
	}
	return nil
}

func (cb *RawContainerCallBack) removeInactiveData(ctx context.Context, sync *assets.TensorSync) error {
	logging.Get().Info().Msgf("remove Inactive container: %+v", sync)
	if cb.parent.enableRedisSearch("rawContainer") {
		return dal.CleanUpRawContainerWithRedis(ctx, cb.parent.rdb.Get(), cb.parent.mustGetRedisSearchClient("rawContainer"), sync.SyncTime, sync.Cluster, sync.NodeName)
	} else {
		return dal.CleanUpRawContainer(ctx, cb.parent.rdb.Get(), sync.SyncTime, sync.Cluster, sync.NodeName)
	}
}

func (cb *RawContainerCallBack) OnTensorResourceEvent(*assets.TensorResource, *assets.TensorResource, assets.Action) error {
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

func (cb *RawContainerCallBack) OnTensorIngress(*assets.TensorIngress, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorService(*assets.TensorService, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorEndpoints(*assets.TensorEndpoints, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorSecret(*assets.TensorSecret, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorPV(*assets.TensorPV, assets.Action) error {
	return nil
}

func (cb *RawContainerCallBack) OnTensorPVC(*assets.TensorPVC, assets.Action) error {
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

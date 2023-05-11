package assets

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	rs "github.com/March-deng/godisearch/redisearch"
	"gitlab.com/security-rd/go-pkg/redisearch"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	corev1 "k8s.io/api/core/v1"
)

var AssetIndices = []*redisearch.RedisIndexSchema{
	{
		Name: "resource",
		Schema: rs.NewSchema(rs.DefaultOptions).
			AddField(rs.NewTagField("name")).
			AddField(rs.NewSortableNumericField("id")).
			AddField(rs.NewTagField("cluster_key")).
			AddField(rs.NewTagField("namespace")).
			AddField(rs.NewNumericField("updated_at")).
			AddField(rs.NewTagField("kind")),
		Definition: rs.NewIndexDefinition().AddPrefix("resource:"),
	},
	{
		Name: "pod",
		Schema: rs.NewSchema(rs.DefaultOptions).
			AddField(rs.NewSortableNumericField("id")).
			AddField(rs.NewTagField("pod_name")).
			AddField(rs.NewTagField("cluster_key")).
			AddField(rs.NewTagField("node_name")).
			AddField(rs.NewTagField("resource_kind")).
			AddField(rs.NewTagField("resource_name")).
			AddField(rs.NewTagField("namespace")).
			AddField(rs.NewTagField("pod_ip")).
			AddField(rs.NewSortableNumericField("updated_at")).
			AddField(rs.NewSortableNumericField("created_at")),
		Definition: rs.NewIndexDefinition().AddPrefix("pod:"),
	},
	{
		Name: "rawContainer",
		Schema: rs.NewSchema(rs.DefaultOptions).
			AddField(rs.NewTagFieldOptions("id", rs.TagFieldOptions{Sortable: true})).
			AddField(rs.NewTagField("status")).
			AddField(rs.NewTagField("k8s_managed")).
			AddField(rs.NewTagField("node_name")).
			AddField(rs.NewTagField("namespace")).
			AddField(rs.NewTagField("pod_name")).
			AddField(rs.NewTagField("name")).
			AddField(rs.NewTagField("resource_name")).
			AddField(rs.NewTagField("cluster_key")).
			AddField(rs.NewSortableNumericField("updated_at")),
		Definition: rs.NewIndexDefinition().AddPrefix("rawContainer:"),
	},
}

const (
	watcherName   = "tensor_resources_listener"
	retryInterval = 2 * time.Minute
	maxRetries    = 5
)

type ResourcesWatcher struct {
	rdb        *databases.RDBInstance
	scannerURL string

	clusterListeners map[string]*ResourcesClusterListener
	clMux            sync.RWMutex

	// redisearch clients
	redisearchClis *redisearch.Client
}

func newResourcesWatcher(rdb *databases.RDBInstance, scannerURL string, redisearchClis *redisearch.Client) *ResourcesWatcher {
	return &ResourcesWatcher{
		rdb:              rdb,
		scannerURL:       scannerURL,
		clusterListeners: make(map[string]*ResourcesClusterListener, 5),
		redisearchClis:   redisearchClis,
	}
}

// BeforeWatchNewCluster called before watch events
func (rl *ResourcesWatcher) BeforeWatchNewCluster(_ context.Context, clusterName string, _ time.Duration) assets.ClusterCallback {
	cl := newResourcesClusterListener(rl)
	rl.addClusterListener(clusterName, cl)
	return cl
}

func (rl *ResourcesWatcher) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.TensorResources2Watch: {},
		assets.Namespaces2Watch:      {},
		assets.Nodes2Watch:           {},
	}
}
func (rl *ResourcesWatcher) Name() string {
	return watcherName
}

func (rl *ResourcesWatcher) addClusterListener(clusterKey string, l *ResourcesClusterListener) {
	rl.clMux.Lock()
	defer rl.clMux.Unlock()

	rl.clusterListeners[clusterKey] = l
}

// call enableRedisSearch before mustGetRedisSearchClient
func (rl *ResourcesWatcher) mustGetRedisSearchClient(modelType string) *rs.Client {
	c, err := rl.redisearchClis.GetIndexClient(modelType)
	if err != nil {
		panic(err)
	}

	return c
}

func (rl *ResourcesWatcher) enableRedisSearch(modelType string) bool {
	if rl.redisearchClis != nil {
		c, err := rl.redisearchClis.GetIndexClient(modelType)
		if err != nil {
			return false
		}
		return c != nil
	}
	return false
}

type resourceEvent struct {
	wtype        assets.WatchedType
	newResource  *assets.TensorResource
	oldResource  *assets.TensorResource
	newNamespace *corev1.Namespace
	newNode      *corev1.Node
	oldNode      *corev1.Node
	clusterKey   string
	action       assets.Action
	updateTime   time.Time
	retryCount   int
}
type ResourcesClusterListener struct {
	parent *ResourcesWatcher
	//clusterKey string
	retryQueue *util.Queue

	refreshTime time.Time
}

func (cl *ResourcesClusterListener) OnRawContainer(*assets.TensorRawContainer, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnSync(*assets.TensorSync) error {
	return nil
}

type ProcFunc func(ctx context.Context, db *gorm.DB, obj interface{}) error

func newResourcesClusterListener(parent *ResourcesWatcher) *ResourcesClusterListener {
	cl := ResourcesClusterListener{
		parent:      parent,
		retryQueue:  util.NewQueue(),
		refreshTime: time.Now(),
	}
	cl.asyncLoop()

	return &cl
}

func (cl *ResourcesClusterListener) batchRetries() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when async loop: %v. Stack: %s", r, debug.Stack())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), retryInterval)
	defer cancel()

	// copy out the items in the queue to retry. Don't keep pull out items. There are possibilities that the function will not end.
	length := cl.retryQueue.Len()
	toRetry := make([]resourceEvent, 0, length)
	for i := 0; i < length; i++ {
		elem, ok := cl.retryQueue.Pop()
		if !ok {
			break
		}
		resEvent, ok := elem.(resourceEvent)
		if ok {
			toRetry = append(toRetry, resEvent)
		}
	}

	for _, resEvent := range toRetry {
		if resEvent.retryCount > maxRetries { // When we try more than max times, we give it up to prevent continuous pressure on database.
			logging.GetLogger().Error().Msgf("retries to the max and fails. event: %+v", resEvent)
			continue
		}
		err := cl.doOnResource(ctx, resEvent) // the failure item will be inserted to the retryChan.
		if err != nil {
			logging.GetLogger().Err(err).Msgf("do on the resource error: %+v", resEvent)
		}
	}
}

func (cl *ResourcesClusterListener) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic when async loop: %v. Stack: %s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(retryInterval)
		defer ticker.Stop()

		for range ticker.C {
			cl.batchRetries()
		}
	}()

}

func (cl *ResourcesClusterListener) sendToRetry(resAction resourceEvent) {
	resAction.retryCount++

	cl.retryQueue.Add(resAction)
}

func (cl *ResourcesClusterListener) OnNodeEvent(newNode, oldNode *corev1.Node, action assets.Action) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when OnNodeEvent: %v. stack: %s", r, debug.Stack())
		}
	}()

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := cl.doOnResource(ctx, resourceEvent{
		wtype:      assets.Nodes2Watch,
		newNode:    newNode,
		oldNode:    oldNode,
		action:     action,
		updateTime: now,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("OnNodeEvent action: %d. new: %+v. old: %+v", action, newNode, oldNode)
		return err
	}
	return nil
}

func (cl *ResourcesClusterListener) doOnResource(ctx context.Context, resEvent resourceEvent) error {
	if resEvent.action == assets.ActionAdd || resEvent.action == assets.ActionUpdate {
		switch resEvent.wtype {
		case assets.TensorResources2Watch:
			if resEvent.newResource == nil {
				return errors.New("newResource is nil")
			}
			if assets.ShouldResourceBeFiltered(resEvent.newResource) {
				return nil
			}
			var upsertErr error

			if cl.parent.enableRedisSearch("resource") {
				_, upsertErr = dal.UpsertResourceWithRedis(ctx, cl.parent.rdb.Get(), cl.parent.mustGetRedisSearchClient("resource"), resEvent.newResource, resEvent.updateTime)
			} else {
				_, upsertErr = dal.UpsertResource(ctx, cl.parent.rdb.Get(), resEvent.newResource, resEvent.updateTime)
			}

			if upsertErr != nil {
				logging.GetLogger().Err(upsertErr).Msgf("upsert resource error. resource: %+v. action: %v", resEvent.newResource, resEvent.action)
				// will periodically retry to write
				cl.sendToRetry(resEvent)
				return upsertErr
			}

		case assets.Namespaces2Watch:
			if resEvent.newNamespace == nil {
				return errors.New("newNamespace is nil")
			}
			_, err := dal.UpsertNamespace(ctx, cl.parent.rdb.Get(), resEvent.newNamespace, resEvent.clusterKey, resEvent.updateTime)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("upsert namespace error. namespace: %+v. action: %v", resEvent.newNamespace, resEvent.action)
				// will periodically retry to write
				cl.sendToRetry(resEvent)
				return err
			}
		case assets.Nodes2Watch:
			if resEvent.newNode == nil {
				return errors.New("newNode is nil")
			}
			_, err := dal.UpsertNode(ctx, cl.parent.rdb.Get(), resEvent.newNode, resEvent.clusterKey, resEvent.updateTime)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("upsert node error. node: %+v. action: %v", resEvent.newNode, resEvent.action)
				// will periodically retry to write
				cl.sendToRetry(resEvent)
				return err
			}
		default:
			logging.GetLogger().Warn().Msgf("watch type not supported. event: %+v", resEvent)
		}
	} else if resEvent.action == assets.ActionDelete {
		switch resEvent.wtype {
		case assets.TensorResources2Watch:
			if resEvent.newResource == nil {
				return errors.New("oldResource is nil")
			}
			if assets.ShouldResourceBeFiltered(resEvent.newResource) {
				return nil
			}
			logging.GetLogger().Info().Msgf("delete resource %s/%s/%s", resEvent.newResource.Kind, resEvent.newResource.Namespace, resEvent.newResource.Name)
			var deleteErr error
			if cl.parent.enableRedisSearch("resource") {
				deleteErr = dal.SoftDeleteResourceWithRedis(ctx, cl.parent.rdb.Get(), cl.parent.mustGetRedisSearchClient("resource"), resEvent.newResource, resEvent.updateTime)
			} else {
				deleteErr = dal.SoftDeleteResource(ctx, cl.parent.rdb.Get(), resEvent.newResource, resEvent.updateTime)
			}

			if deleteErr != nil {
				logging.GetLogger().Err(deleteErr).Msgf("delete resource error. resource: %+v. action: %v", resEvent.newResource, resEvent.action)
				// will periodically retry to write
				cl.sendToRetry(resEvent)
				return deleteErr
			}

		case assets.Namespaces2Watch:
			if resEvent.newNamespace == nil {
				return errors.New("oldNamespace is nil")
			}
			err := dal.SoftDeleteNamespace(ctx, cl.parent.rdb.Get(), resEvent.newNamespace, resEvent.clusterKey, resEvent.updateTime)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("delete namespace error. namespace: %+v. action: %v", resEvent.newNamespace, resEvent.action)
				// will periodically retry to write
				cl.sendToRetry(resEvent)
				return err
			}
		case assets.Nodes2Watch:
			if resEvent.newNode == nil {
				return errors.New("oldNode is nil")
			}
			err := dal.SoftDeleteNode(ctx, cl.parent.rdb.Get(), resEvent.newNode, resEvent.clusterKey, resEvent.updateTime)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("delete node error. node: %+v. action: %v", resEvent.oldNode, resEvent.action)
				// will periodically retry to write
				cl.sendToRetry(resEvent)
				return err
			}
		default:
			logging.GetLogger().Warn().Msgf("watch type not supported. event: %+v", resEvent)
		}
	}

	return nil
}
func (cl *ResourcesClusterListener) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.Action) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when OnTensorResourceEvent: %v. stack: %s", r, debug.Stack())
		}
	}()

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := cl.doOnResource(ctx, resourceEvent{
		wtype:       assets.TensorResources2Watch,
		newResource: newResource,
		oldResource: nil,
		action:      action,
		updateTime:  now,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("on tensorResource action: %d. newResource: %+v. old: %+v", action, newResource, oldResource)
		return err
	}
	return nil
}

func (cl *ResourcesClusterListener) OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action assets.Action) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when OnNamespaceEvent: %v. stack: %s", r, debug.Stack())
		}
	}()

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := cl.doOnResource(ctx, resourceEvent{
		wtype:        assets.Namespaces2Watch,
		newNamespace: newNs,
		action:       action,
		updateTime:   now,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("OnNamespaceEvent action: %d. new: %+v. old: %+v", action, newNs, oldNs)
		return err
	}
	return nil
}

func (cl *ResourcesClusterListener) OnTensorNamespace(namespace *assets.TensorNamespace, action assets.Action) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when OnNamespaceEvent: %v. stack: %s", r, debug.Stack())
		}
	}()

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := cl.doOnResource(ctx, resourceEvent{
		clusterKey:   namespace.Cluster,
		wtype:        assets.Namespaces2Watch,
		newNamespace: namespace.Namespace,
		action:       action,
		updateTime:   now,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("OnNamespaceEvent action: %d. new: %+v.", action, namespace)
		return err
	}
	return nil
}

func (cl *ResourcesClusterListener) OnTensorNode(node *assets.TensorNode, action assets.Action) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when OnNodeEvent: %v. stack: %s", r, debug.Stack())
		}
	}()

	if node == nil {
		return fmt.Errorf("invalid node")
	}
	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := cl.doOnResource(ctx, resourceEvent{
		clusterKey: node.Cluster,
		wtype:      assets.Nodes2Watch,
		newNode:    node.Node,
		oldNode:    nil,
		action:     action,
		updateTime: now,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("OnNodeEvent action: %d. new: %+v.", action, node)
		return err
	}
	return nil
}

func (cl *ResourcesClusterListener) AfterDataSynced(ctx context.Context, dataSynced bool, clusterKey string) {
	if !dataSynced {
		logging.GetLogger().Warn().Msg("AfterDataSynced dataSynced=false")
		return
	}

	err := dal.CleanUpUnUpdatedResourceContainers(ctx, cl.parent.rdb.Get(), cl.refreshTime, clusterKey)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CleanUpUnUpdatedResourceContainers error. refreshTime: %v", cl.refreshTime)
	}

	if cl.parent.enableRedisSearch("resource") {
		err = dal.CleanUpUnUpdatedResourcesWithRedis(ctx, cl.parent.rdb.Get(), cl.parent.mustGetRedisSearchClient("resource"), cl.refreshTime, clusterKey)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("CleanUpUnUpdatedResources error. refreshTime: %v", cl.refreshTime)
		}
	} else {
		err = dal.CleanUpUnUpdatedResources(ctx, cl.parent.rdb.Get(), cl.refreshTime, clusterKey)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("CleanUpUnUpdatedResources error. refreshTime: %v", cl.refreshTime)
		}
	}

	err = dal.CleanUpUnUpdatedNamespaces(ctx, cl.parent.rdb.Get(), cl.refreshTime, clusterKey)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CleanUpUnUpdatedNamespaces error. refreshTime: %v", cl.refreshTime)
	}

	err = dal.CleanUpUnUpdatedNodes(ctx, cl.parent.rdb.Get(), cl.refreshTime, clusterKey)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CleanUpUnUpdatedNodes error. refreshTime: %v", cl.refreshTime)
	}
}

func (cl *ResourcesClusterListener) Name() string {
	return cl.parent.Name()
}

func (cl *ResourcesClusterListener) OnTensorPod(pod *assets.TensorPod, action assets.Action) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when OnTensorPod: %v. stack: %s", r, debug.Stack())
		}
	}()

	if action == assets.ActionDelete {
		now := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		logging.GetLogger().Debug().Msgf("deleting pod %s/%s/%s", pod.Cluster, pod.Namespace, pod.Name)
		err := cl.doOnResource(ctx, resourceEvent{
			wtype: assets.TensorResources2Watch,
			newResource: &assets.TensorResource{
				ObjectMeta: *pod.ObjectMeta.DeepCopy(),
				Cluster:    pod.Cluster,
				Kind:       assets.KindPodNoOwner,
				CreateTime: time.Time{},
			},
			oldResource: nil,
			action:      action,
			updateTime:  now,
		})
		if err != nil {
			logging.GetLogger().Err(err).Msgf("on OnTensorPod action: %d. pod: %+v.", action, pod)
			return err
		}
	}
	return nil
}

func (cl *ResourcesClusterListener) OnHoneyspot(*assets.TensorHoneySpot, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorRole(*assets.TensorRole, assets.Action) error {
	return nil
}

func (cl *ResourcesClusterListener) OnTensorClusterRole(*assets.TensorClusterRole, assets.Action) error {
	return nil
}

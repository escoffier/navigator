package assets

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	watcherName   = "tensor_resources_listener"
	retryInterval = 2 * time.Minute
	maxRetries    = 5
)

type ResourcesWatcher struct {
	rdb        *rdbtools.GormWrapper
	scannerURL string

	clusterListeners map[string]*ResourcesClusterListener
	clMux            sync.RWMutex
}

func newResourcesWatcher(rdb *rdbtools.GormWrapper, scannerURL string) *ResourcesWatcher {
	return &ResourcesWatcher{
		rdb:              rdb,
		scannerURL:       scannerURL,
		clusterListeners: make(map[string]*ResourcesClusterListener, 5),
	}
}

// called before watch events
func (rl *ResourcesWatcher) BeforWatchNewCluster(ctx context.Context, clusterName string, resyncTTL time.Duration) assets.ClusterCallback {
	cl := newResourcesClusterListener(rl, clusterName)
	rl.addClusterListener(clusterName, cl)
	return cl
}

func (rl *ResourcesWatcher) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.TensorResources2Watch: {},
		assets.Namespaces2Watch:      {},
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

func (rl *ResourcesWatcher) getClusters() []string {
	rl.clMux.RLock()
	defer rl.clMux.RUnlock()

	clusters := make([]string, 0, len(rl.clusterListeners))
	for clusterKey := range rl.clusterListeners {
		clusters = append(clusters, clusterKey)
	}
	return clusters
}
func (rl *ResourcesWatcher) getClusterListener(clusterKey string) (*ResourcesClusterListener, bool) {
	rl.clMux.RLock()
	defer rl.clMux.RUnlock()

	l, ok := rl.clusterListeners[clusterKey]
	return l, ok
}

type resourceEvent struct {
	wtype        assets.WatchedType
	newResource  *assets.TensorResource
	oldResource  *assets.TensorResource
	newNamespace *corev1.Namespace
	oldNamespace *corev1.Namespace
	action       assets.AssetsAction
	updateTime   time.Time
	retryCount   int
}
type ResourcesClusterListener struct {
	parent     *ResourcesWatcher
	clusterKey string
	retryQueue *util.Queue

	refreshTime time.Time
}

func newResourcesClusterListener(parent *ResourcesWatcher, clusterKey string) *ResourcesClusterListener {
	cl := ResourcesClusterListener{
		parent:      parent,
		clusterKey:  clusterKey,
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
		toRetry = append(toRetry, resEvent)
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

		for {
			select {
			case <-ticker.C:
				cl.batchRetries()
			}
		}
	}()

}

func (cl *ResourcesClusterListener) sendToRetry(resAction resourceEvent) {
	resAction.retryCount++

	cl.retryQueue.Add(resAction)
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
			_, err := dal.UpsertResource(ctx, cl.parent.rdb, resEvent.newResource, resEvent.updateTime)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("upsert resource error. resource: %+v. action: %v", resEvent.newResource, resEvent.action)
				// will periodically retry to write
				cl.sendToRetry(resEvent)
				return err
			}
		case assets.Namespaces2Watch:
			if resEvent.newNamespace == nil {
				return errors.New("newNamespace is nil")
			}
			_, err := dal.UpsertNamespace(ctx, cl.parent.rdb, resEvent.newNamespace, cl.clusterKey, resEvent.updateTime)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("upsert namespace error. namespace: %+v. action: %v", resEvent.newNamespace, resEvent.action)
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
			if resEvent.oldResource == nil {
				return errors.New("oldResource is nil")
			}
			if assets.ShouldResourceBeFiltered(resEvent.oldResource) {
				return nil
			}
			err := dal.SoftDeleteResource(ctx, cl.parent.rdb, resEvent.oldResource, resEvent.updateTime)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("delete resource error. resource: %+v. action: %v", resEvent.oldResource, resEvent.action)
				// will periodically retry to write
				cl.sendToRetry(resEvent)
				return err
			}
		case assets.Namespaces2Watch:
			if resEvent.oldNamespace == nil {
				return errors.New("oldNamespace is nil")
			}
			err := dal.SoftDeleteNamespace(ctx, cl.parent.rdb, resEvent.oldNamespace, cl.clusterKey, resEvent.updateTime)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("delete namespace error. namespace: %+v. action: %v", resEvent.oldNamespace, resEvent.action)
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
func (cl *ResourcesClusterListener) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when OnTensorResourceEvent: %v. stack: %s", r, debug.Stack())
		}
	}()

	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := cl.doOnResource(ctx, resourceEvent{
		wtype:       assets.TensorResources2Watch,
		newResource: newResource,
		oldResource: oldResource,
		action:      action,
		updateTime:  now,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("on tensorResource action: %s. newResource: %+v. old: %+v", action, newResource, oldResource)
		return err
	}
	return nil
}

func (cl *ResourcesClusterListener) OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action assets.AssetsAction) error {
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
		oldNamespace: oldNs,
		action:       action,
		updateTime:   now,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msgf("OnNamespaceEvent action: %s. new: %+v. old: %+v", action, newNs, oldNs)
		return err
	}
	return nil
}

func (cl *ResourcesClusterListener) AfterDataSynced(ctx context.Context, dataSynced bool) {
	if !dataSynced {
		return
	}

	err := dal.CleanUpUnUpdatedResourceContainers(ctx, cl.parent.rdb, cl.refreshTime, cl.clusterKey)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CleanUpUnUpdatedResourceContainers error. refreshTime: %v", cl.refreshTime)
	}
	err = dal.CleanUpUnUpdatedResources(ctx, cl.parent.rdb, cl.refreshTime, cl.clusterKey)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CleanUpUnUpdatedResources error. refreshTime: %v", cl.refreshTime)
	}

	err = dal.CleanUpUnUpdatedNamespaces(ctx, cl.parent.rdb, cl.refreshTime, cl.clusterKey)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("CleanUpUnUpdatedNamespaces error. refreshTime: %v", cl.refreshTime)
	}

}

func (cl *ResourcesClusterListener) Name() string {
	return cl.parent.Name()
}

func (cl *ResourcesClusterListener) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnRoleEvent(newRole, oldRole *rbacv1.Role, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnClusterRoleEvent(newCRole, oldCRole *rbacv1.ClusterRole, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnRoleBindingEvent(newB, oldB *rbacv1.RoleBinding, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnClusterRoleBindingEvent(newB, oldB *rbacv1.ClusterRoleBinding, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *ResourcesClusterListener) OnServiceAccountEvent(newSa, oldSa *corev1.ServiceAccount, action assets.AssetsAction) error {
	// do nothing
	return nil
}

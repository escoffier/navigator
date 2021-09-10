package assets

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

var (
	instance *TensorResourcesService
	rlOnce   sync.Once
)

func InitResourcesService(postgre *rdbtools.GormWrapper, scannerURL string) error {
	rlOnce.Do(func() {
		instance = newTensorResourcesService(postgre, scannerURL)
	})
	return nil
}

func GetResourcesService(ctx context.Context) (*TensorResourcesService, bool) {
	return instance, instance != nil
}

const (
	watcherName   = "tensor_resources_listener"
	retryInterval = 2 * time.Minute
	maxRetries    = 5
)

type TensorResourcesService struct {
	rdb              *rdbtools.GormWrapper
	clusterListeners map[string]*TensorResourcesClusterListener
	scannerURL       string
	resourceWatcher  *assets.Watcher

	clMux      sync.RWMutex
	watcherMut sync.RWMutex
}

func newTensorResourcesService(rdb *rdbtools.GormWrapper, scannerURL string) *TensorResourcesService {
	return &TensorResourcesService{
		rdb:              rdb,
		scannerURL:       scannerURL,
		clusterListeners: make(map[string]*TensorResourcesClusterListener, 5),
	}
}

func (rl *TensorResourcesService) GetClusters(ctx context.Context, offset, limit int) ([]*model.TensorCluster, int64, error) {
	return dal.GetClusters(ctx, rl.rdb, offset, limit)
}

func (rl *TensorResourcesService) GetClusterByKey(ctx context.Context, key string) *int64 {
	return dal.GetClustersByKey(ctx, rl.rdb, key)
}

func (rl *TensorResourcesService) AddCluster(ctx context.Context, cluster *model.TensorCluster) error {
	// TODO create the k8s client and so on
	return dal.AddCluster(ctx, rl.rdb, cluster)
}

func (rl *TensorResourcesService) UpdateCluster(ctx context.Context, clusterKey, newClusterName, newDescription string) error {
	return dal.UpdateCluster(ctx, rl.rdb, clusterKey, newClusterName, newDescription)
}

func (rl *TensorResourcesService) DeleteCluster(ctx context.Context, clusterKey string) error {
	return dal.DeleteCluster(ctx, rl.rdb, clusterKey)
}

func (rl *TensorResourcesService) GetResources(ctx context.Context, queryOptions *dal.ResourcesQueryOption, offset, limit int) ([]*model.TensorResource, int64, error) {
	resources, err := dal.GetResources(ctx, rl.rdb, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	resCnt, err := dal.CountResources(ctx, rl.rdb, queryOptions)
	if err != nil {
		return nil, 0, err
	}
	return resources, resCnt, nil
}
func (rl *TensorResourcesService) GetNamespaces(ctx context.Context, clusterKey, nameQuery string, offset, limit int) ([]*model.TensorNamespace, int64, error) {
	ns, err := dal.GetNamespacesByCluster(ctx, rl.rdb, clusterKey, nameQuery, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	cnt, err := dal.CountNamespaces(ctx, rl.rdb, clusterKey, nameQuery)
	if err != nil {
		return nil, 0, err
	}
	return ns, cnt, nil
}

func (rl *TensorResourcesService) GetResourcePods(ctx context.Context, clusterKey, namespace, resKind, resName string) ([]*model.PodResourceRelation, error) {
	return dal.GetResourcePodsList(ctx, rl.rdb, clusterKey, namespace, resKind, resName)
}
func (rl *TensorResourcesService) GetResourceContainers(ctx context.Context, queryOptions *dal.ResContainersQueryOption, offset, limit int) ([]*model.TensorContainer, int64, error) {
	containers, err := dal.GetResourceContainers(ctx, rl.rdb, queryOptions, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	cnt, err := dal.CountResourceContainers(ctx, rl.rdb, queryOptions)
	return containers, cnt, err
}

func (rl *TensorResourcesService) GetImagesWithGivenVuln(ctx context.Context, vulnName string) ([]*model.ImageInfo, error) {
	return dal.GetImagesWithGivenVuln(ctx, rl.scannerURL, vulnName)
}

func getImageIDFrom(m *model.ImageInfo) string {
	lib := m.Library
	if strings.Index(m.Library, "http://") == 0 {
		lib = m.Library[7:]
	} else if strings.Index(m.Library, "https://") == 0 {
		lib = m.Library[8:]
	}
	return fmt.Sprintf("%s/%s:%s", lib, m.FullRepoName, m.Tags)
}
func (rl *TensorResourcesService) GetResourceContainersWithGivenVuln(ctx context.Context, vulnName string, offset, limit int) ([]*model.TensorContainer, int64, error) {
	images, err := rl.GetImagesWithGivenVuln(ctx, vulnName)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "GetImagesWithGivenVuln %s error", vulnName)
		return nil, 0, err
	}

	imageIDs := make([]string, 0, len(images))
	for _, image := range images {
		imageIDs = append(imageIDs, getImageIDFrom(image))
	}

	containers, totalCnt, err := rl.GetResourceContainers(ctx, dal.ResourceContainersQuery().WithInConditionCustom("image", imageIDs), offset, limit)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "GetResourceContainers %s error. imageList: %v", vulnName, imageIDs)
		return nil, 0, err
	}

	return containers, totalCnt, nil
}

func (rl *TensorResourcesService) addClusterListener(clusterKey string, l *TensorResourcesClusterListener) {
	rl.clMux.Lock()
	defer rl.clMux.Unlock()

	rl.clusterListeners[clusterKey] = l
}

func (rl *TensorResourcesService) getClusters() []string {
	rl.clMux.RLock()
	defer rl.clMux.RUnlock()

	clusters := make([]string, 0, len(rl.clusterListeners))
	for clusterKey := range rl.clusterListeners {
		clusters = append(clusters, clusterKey)
	}
	return clusters
}
func (rl *TensorResourcesService) getClusterListener(clusterKey string) (*TensorResourcesClusterListener, bool) {
	rl.clMux.RLock()
	defer rl.clMux.RUnlock()

	l, ok := rl.clusterListeners[clusterKey]
	return l, ok
}

// called before watch events
func (rl *TensorResourcesService) BeforWatchNewCluster(ctx context.Context, clusterName string, resyncTTL time.Duration) assets.ClusterCallback {
	cl := newTensorResourcesClusterListener(rl, clusterName)
	rl.addClusterListener(clusterName, cl)
	return cl
}

func (rl *TensorResourcesService) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.TensorResources2Watch: {},
		assets.Namespaces2Watch:      {},
	}
}
func (rl *TensorResourcesService) Name() string {
	return watcherName
}

func (rl *TensorResourcesService) SetWatcher(watcher *assets.Watcher) {
	rl.watcherMut.Lock()
	defer rl.watcherMut.Unlock()
	rl.resourceWatcher = watcher
}

func (rl *TensorResourcesService) GetWatcher() *assets.Watcher {
	rl.watcherMut.RLock()
	defer rl.watcherMut.RUnlock()
	return rl.resourceWatcher
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
type TensorResourcesClusterListener struct {
	parent     *TensorResourcesService
	clusterKey string
	retryQueue *util.Queue

	refreshTime time.Time
}

func newTensorResourcesClusterListener(parent *TensorResourcesService, clusterKey string) *TensorResourcesClusterListener {
	cl := TensorResourcesClusterListener{
		parent:      parent,
		clusterKey:  clusterKey,
		retryQueue:  util.NewQueue(),
		refreshTime: time.Now(),
	}
	cl.asyncLoop()

	return &cl
}

func (cl *TensorResourcesClusterListener) batchRetries() {
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

func (cl *TensorResourcesClusterListener) asyncLoop() {
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

func (cl *TensorResourcesClusterListener) sendToRetry(resAction resourceEvent) {
	resAction.retryCount++

	cl.retryQueue.Add(resAction)
}

func (cl *TensorResourcesClusterListener) doOnResource(ctx context.Context, resEvent resourceEvent) error {
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
func (cl *TensorResourcesClusterListener) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
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

func (cl *TensorResourcesClusterListener) OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action assets.AssetsAction) error {
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

func (cl *TensorResourcesClusterListener) AfterDataSynced(ctx context.Context, dataSynced bool) {
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

func (cl *TensorResourcesClusterListener) Name() string {
	return cl.parent.Name()
}

func (cl *TensorResourcesClusterListener) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *TensorResourcesClusterListener) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *TensorResourcesClusterListener) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *TensorResourcesClusterListener) OnRoleEvent(newRole, oldRole *rbacv1.Role, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *TensorResourcesClusterListener) OnClusterRoleEvent(newCRole, oldCRole *rbacv1.ClusterRole, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *TensorResourcesClusterListener) OnRoleBindingEvent(newB, oldB *rbacv1.RoleBinding, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *TensorResourcesClusterListener) OnClusterRoleBindingEvent(newB, oldB *rbacv1.ClusterRoleBinding, action assets.AssetsAction) error {
	// do nothing
	return nil
}
func (cl *TensorResourcesClusterListener) OnServiceAccountEvent(newSa, oldSa *corev1.ServiceAccount, action assets.AssetsAction) error {
	// do nothing
	return nil
}

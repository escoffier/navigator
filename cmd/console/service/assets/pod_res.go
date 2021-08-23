package assets

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var defaultRefreshTime = time.Now().Add(-1 * time.Hour).Unix()
var (
	podResInstance *PodResourcesService
	once           sync.Once
)

func Init(redisCli *redis.Client, postgresDB *rdbtools.GormWrapper) error {
	var err error
	once.Do(func() {
		if redisCli == nil || postgresDB == nil {
			err = errors.New("dependency is nil")
			return
		}
		podResInstance = newAssetsInResources(redisCli, postgresDB)
	})
	return err
}

func GetPodResourcesService(ctx context.Context) (*PodResourcesService, bool) {
	return podResInstance, podResInstance != nil
}

type PodResourcesService struct {
	sync.RWMutex

	postgresDB       *rdbtools.GormWrapper
	redisCli         *redis.Client
	clusterCallbacks map[string]*PodResourcesClusterCallback
	syncedClusters   map[string]struct{}
}

type PodResourcesClusterCallback struct {
	cluster          string
	parent           *PodResourcesService
	refreshTimestamp int64
	resyncInterval   time.Duration

	rsToDeploymentCache *sync.Map // string(namespace/name) -> *metav1.OwnerReference
}

func newAssetsInResources(redisCli *redis.Client, postgresDB *rdbtools.GormWrapper) *PodResourcesService {
	return &PodResourcesService{
		redisCli:         redisCli,
		postgresDB:       postgresDB,
		clusterCallbacks: make(map[string]*PodResourcesClusterCallback, 2),
		syncedClusters:   make(map[string]struct{}),
	}
}

func (cb *PodResourcesService) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch:            {},
		assets.TensorResources2Watch: {},
	}
}

func (cb *PodResourcesService) setClusterDataSynced(cluster string) {
	cb.Lock()
	defer cb.Unlock()

	cb.syncedClusters[cluster] = struct{}{}
}

func (cb *PodResourcesService) getClusterRefreshTimestamp(clusterName string) (int64, bool) {
	cb.RLock()
	defer cb.RUnlock()

	ccb, exist := cb.clusterCallbacks[clusterName]
	if !exist {
		return 0, false
	}
	ts := ccb.refreshUnixTimestamp()
	return ts, ts > 0
}

// BeforWatchNewCluster called before watch events
func (cb *PodResourcesService) BeforWatchNewCluster(ctx context.Context, clusterName string, resyncInterval time.Duration) assets.ClusterCallback {
	logging.GetLogger().Info().Msgf("service assets before watch new cluster %s called.", clusterName)

	ccb := &PodResourcesClusterCallback{
		cluster:             clusterName,
		parent:              cb,
		refreshTimestamp:    time.Now().Unix(),
		rsToDeploymentCache: new(sync.Map),
		resyncInterval:      resyncInterval,
	}
	cb.Lock()
	defer cb.Unlock()
	cb.clusterCallbacks[clusterName] = ccb

	return ccb
}

// Name returns the name
func (cb *PodResourcesService) Name() string {
	return "onlineVulns"
}

func (cb *PodResourcesClusterCallback) refreshUnixTimestamp() int64 {
	return atomic.LoadInt64(&cb.refreshTimestamp)
}

func (cb *PodResourcesClusterCallback) refreshTime() time.Time {
	return time.Unix(cb.refreshUnixTimestamp(), 0)
}

func (cb *PodResourcesClusterCallback) getUpperOwnerOfPod(pod *corev1.Pod) (*metav1.OwnerReference, bool) {
	if pod == nil {
		return nil, false
	}
	owner := metav1.GetControllerOf(pod)
	if owner != nil && owner.Kind == "ReplicaSet" {
		ownerOfOwner, ok := cb.getOwnerRefOfRS(owner.Name, pod.Namespace)
		if ok && ownerOfOwner != nil {
			owner = ownerOfOwner
		}
	}
	return owner, owner != nil
}
func (cb *PodResourcesClusterCallback) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if action == assets.ActionDelete {
		if oldPod == nil {
			return errors.New("not given old pod")
		}

		rerr := dal.DeletePodResourceRelationInRDB(ctx, cb.parent.postgresDB, oldPod, cb.cluster)
		if rerr != nil {
			logging.GetLogger().Err(rerr).Msg("delete pod resource rel in rdb error")
		}
		cerr := dal.DeletePodResourceRelation(ctx, cb.parent.redisCli, oldPod, cb.cluster)
		if cerr != nil {
			logging.GetLogger().Err(cerr).Msg("delete pod resource rel in cache error")
		}
	} else if action == assets.ActionAdd || action == assets.ActionUpdate {
		if newPod == nil {
			return errors.New("not given new pod")
		}
		owner, _ := cb.getUpperOwnerOfPod(newPod)
		var ownerName, ownerKind string
		if owner == nil {
			ownerName = "NO_OWNER"
			ownerKind = "NO_OWNER"
		} else {
			ownerName = owner.Name
			ownerKind = owner.Kind
		}

		rerr := dal.UpsertPodResourceRelationInRDB(ctx, cb.parent.postgresDB, newPod, ownerName, ownerKind, cb.cluster, time.Now())
		if rerr != nil {
			logging.GetLogger().Err(rerr).Msg("upsert pod resource rel in rdb error")
		}
		cerr := dal.UpsertPodResourceRelation(ctx, cb.parent.redisCli, newPod, ownerName, ownerKind, cb.cluster, 2*cb.resyncInterval)
		if cerr != nil {
			logging.GetLogger().Err(rerr).Msg("upsert pod resource rel in cache error")
		}
	}

	return nil
}

func (cb *PodResourcesClusterCallback) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// ignore endpoint events
	return nil
}
func (cb *PodResourcesClusterCallback) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	return nil
}

func (cb *PodResourcesClusterCallback) removeReplicaSet(name string, namespace string) {
	cb.rsToDeploymentCache.Delete(getKeyFromRS(name, namespace))
}

func getKeyFromRS(name string, namespace string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func (cb *PodResourcesClusterCallback) updateReplicaSet(rs *appsv1.ReplicaSet) {
	if rs == nil {
		return
	}
	controller := metav1.GetControllerOf(rs)
	if controller != nil {
		cb.rsToDeploymentCache.Store(getKeyFromRS(rs.Name, rs.Namespace), controller)
	}
}
func (cb *PodResourcesClusterCallback) getOwnerRefOfRS(name string, namespace string) (*metav1.OwnerReference, bool) {
	item, ok := cb.rsToDeploymentCache.Load(getKeyFromRS(name, namespace))
	if !ok {
		return nil, false
	}
	owner, ok := item.(*metav1.OwnerReference)
	if !ok {
		return nil, false
	}
	return owner, true
}

func (cb *PodResourcesClusterCallback) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
	switch action {
	case assets.ActionDelete:
		if oldResource == nil {
			return errors.New("nil old obj")
		}
		if oldResource.Kind == assets.KindReplicaSet {
			cb.removeReplicaSet(oldResource.Name, oldResource.Namespace)
		}

	case assets.ActionUpdate, assets.ActionAdd:
		if newResource == nil {
			return errors.New("nil old obj")
		}
		if newResource.Kind == assets.KindReplicaSet {
			rs, ok := newResource.GetReplicaSet()
			if ok {
				cb.updateReplicaSet(rs)
			}
		}
	}
	return nil
}

func (cb *PodResourcesClusterCallback) AfterDataSynced(ctx context.Context, dataSynced bool) {
	if dataSynced {
		cb.parent.setClusterDataSynced(cb.cluster)
		cb.removeInactiveData(ctx)
	}
}

func (cb *PodResourcesClusterCallback) removeInactiveData(ctx context.Context) error {
	return dal.CleanUpPodResourceRelationsInRDB(ctx, cb.parent.postgresDB, cb.refreshTime(), cb.cluster)
}

func (cb *PodResourcesClusterCallback) OnRoleEvent(newRole, oldRole *rbacv1.Role, action assets.AssetsAction) error {
	return nil
}
func (cb *PodResourcesClusterCallback) OnClusterRoleEvent(newCRole, oldCRole *rbacv1.ClusterRole, action assets.AssetsAction) error {
	return nil
}
func (cb *PodResourcesClusterCallback) OnRoleBindingEvent(newB, oldB *rbacv1.RoleBinding, action assets.AssetsAction) error {
	return nil
}
func (cb *PodResourcesClusterCallback) OnClusterRoleBindingEvent(newB, oldB *rbacv1.ClusterRoleBinding, action assets.AssetsAction) error {
	return nil
}
func (cb *PodResourcesClusterCallback) OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action assets.AssetsAction) error {
	return nil
}
func (cb *PodResourcesClusterCallback) OnServiceAccountEvent(newSa, oldSa *corev1.ServiceAccount, action assets.AssetsAction) error {
	return nil
}

func (cb *PodResourcesClusterCallback) Name() string {
	return cb.parent.Name()
}

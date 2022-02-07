package assets

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodResourcesService struct {
	sync.RWMutex

	rdb              *rdbtools.GormWrapper
	redisCli         *redis.Client
	clusterCallbacks map[string]*PodResourcesClusterCallback
	syncedClusters   map[string]struct{}
}

type podEvent struct {
	pod        *corev1.Pod
	action     assets.AssetsAction
	updateTime time.Time
}
type PodResourcesClusterCallback struct {
	cluster          string
	parent           *PodResourcesService
	refreshTimestamp int64
	resyncInterval   time.Duration

	rsToDeploymentCache *sync.Map // string(namespace/name) -> *metav1.OwnerReference
	rsUpdateUnixTime    int64
	inputQueue          *util.Queue
	consumed            int32
}

func newPodResourcesService(redisCli *redis.Client, rdb *rdbtools.GormWrapper) *PodResourcesService {
	return &PodResourcesService{
		redisCli:         redisCli,
		rdb:              rdb,
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

type syncSignal struct{}

// BeforWatchNewCluster called before watch events
func (cb *PodResourcesService) BeforWatchNewCluster(ctx context.Context, clusterName string, resyncInterval time.Duration) assets.ClusterCallback {
	logging.GetLogger().Info().Msgf("service assets before watch new cluster %s called.", clusterName)

	ccb := &PodResourcesClusterCallback{
		cluster:             clusterName,
		parent:              cb,
		refreshTimestamp:    time.Now().Unix(),
		rsToDeploymentCache: new(sync.Map),
		resyncInterval:      resyncInterval,
		inputQueue:          util.NewQueue(),
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		// wait for the time that the replicasets are not updated for a duration(synced). max wait for 5 minutes
		for i := 0; i < 30; i++ {
			now := <-ticker.C
			if now.Unix()-atomic.LoadInt64(&ccb.rsUpdateUnixTime) >= 30 {
				break
			}
		}

		consumed := ccb.tryToConsumePods()
		if consumed {
			logging.GetLogger().Info().Msg("start to consume pods")
		}
	}()
	cb.Lock()
	defer cb.Unlock()
	cb.clusterCallbacks[clusterName] = ccb

	return ccb
}

// Name returns the name
func (cb *PodResourcesService) Name() string {
	return "podResources"
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
		} else {
			pos := strings.LastIndexByte(owner.Name, '-')
			if pos < 0 {
				return owner, true
			}
			ownerOwnerName := owner.Name[0:pos]

			cnt, err := dal.CountResources(context.Background(), cb.parent.rdb.Get(), dal.ResourcesQuery().WithCluster(cb.cluster).WithNamespace(pod.Namespace).WithResourceKind(assets.KindDeployment).WithResourceName(ownerOwnerName))
			if err == nil && cnt > 0 {
				return &metav1.OwnerReference{Name: ownerOwnerName, Kind: string(assets.KindDeployment)}, true
			}
		}
	}
	return owner, owner != nil
}

func (cb *PodResourcesClusterCallback) OnNodeEvent(newNode, oldNode *corev1.Node, action assets.AssetsAction) error {
	return nil
}

func (cb *PodResourcesClusterCallback) sendInput(ctx context.Context, e podEvent) error {
	cb.inputQueue.Add(e)
	return nil
}

func (cb *PodResourcesClusterCallback) doOnPodEvent(ctx context.Context, e podEvent) (err error) {
	defer func() {
		if r := recover(); r != nil {
			podName := ""
			if e.pod != nil {
				podName = fmt.Sprintf("%s/%s", e.pod.Namespace, e.pod.Name)
			}
			logging.GetLogger().Error().Msgf("Panic when do on pod (%s) event: %v. event: %+v", podName, r, e)
			err = errors.New("panic")
		}
	}()

	tctx, cancel := context.WithTimeout(ctx, 8000*time.Millisecond)
	defer cancel()

	switch e.action {
	case assets.ActionDelete:
		rerr := dal.DeletePodResourceRelationInRDB(tctx, cb.parent.rdb, e.pod, cb.cluster)
		if rerr != nil {
			logging.GetLogger().Err(rerr).Msg("delete pod resource rel in rdb error")
		}
		cerr := dal.DeletePodResourceRelation(tctx, cb.parent.redisCli, e.pod, cb.cluster)
		if cerr != nil {
			logging.GetLogger().Err(cerr).Msg("delete pod resource rel in cache error")
		}
	case assets.ActionUpdate, assets.ActionAdd:
		owner, _ := cb.getUpperOwnerOfPod(e.pod)
		var ownerName, ownerKind string
		if owner == nil {
			ownerName = "NO_OWNER"
			ownerKind = "NO_OWNER"
		} else {
			ownerName = owner.Name
			ownerKind = owner.Kind
		}
		rerr := dal.UpsertPodResourceRelationInRDB(tctx, cb.parent.rdb, e.pod, ownerName, ownerKind, cb.cluster, e.updateTime)
		if rerr != nil {
			logging.GetLogger().Err(rerr).Msg("upsert pod resource rel in rdb error")
		}
		cerr := dal.UpsertPodResourceRelation(tctx, cb.parent.redisCli, e.pod, ownerName, ownerKind, cb.cluster, 2*cb.resyncInterval)
		if cerr != nil {
			logging.GetLogger().Err(rerr).Msg("upsert pod resource rel in cache error")
		}

	}
	return nil
}

func (cb *PodResourcesClusterCallback) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if action == assets.ActionDelete {
		if oldPod == nil {
			return errors.New("not given old pod")
		}

		return cb.sendInput(ctx, podEvent{
			pod:        oldPod,
			action:     action,
			updateTime: time.Now(),
		})
	} else if action == assets.ActionAdd || action == assets.ActionUpdate {
		if newPod == nil {
			return errors.New("not given new pod")
		}

		return cb.sendInput(ctx, podEvent{
			pod:        newPod,
			action:     action,
			updateTime: time.Now(),
		})

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
		atomic.StoreInt64(&cb.rsUpdateUnixTime, time.Now().Unix())
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

func (cb *PodResourcesClusterCallback) tryToConsumePods() bool {
	toConsume := atomic.CompareAndSwapInt32(&cb.consumed, 0, 1)
	if toConsume {
		cb.inputQueue.Consume(func(item interface{}) {
			switch typed := item.(type) {
			case syncSignal:
				err := cb.removeInactiveData(context.Background())
				if err != nil {
					logging.GetLogger().Err(err).Msg("do removeInactiveData error")
				} else {
					logging.GetLogger().Info().Msg("cluster information scyned")
				}
			case podEvent:
				err := cb.doOnPodEvent(context.Background(), typed)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("do on pod event %+v error", typed)
				}
			}
		})
		return true
	}
	return false
}
func (cb *PodResourcesClusterCallback) AfterDataSynced(ctx context.Context, dataSynced bool) {
	if dataSynced {
		cb.inputQueue.Add(syncSignal{})
	}
}

func (cb *PodResourcesClusterCallback) removeInactiveData(ctx context.Context) error {
	return dal.CleanUpPodResourceRelationsInRDB(ctx, cb.parent.rdb, cb.refreshTime(), cb.cluster)
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

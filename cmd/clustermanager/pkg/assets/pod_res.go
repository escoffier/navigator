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
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodResourcesService struct {
	sync.RWMutex
	rdb              *databases.RDBInstance
	redisCli         *redis.Client
	clusterCallbacks map[string]*PodResourcesClusterCallback
	syncedClusters   map[string]struct{}
}

type podEvent struct {
	pod        *assets.TensorPod
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

func newPodResourcesService(redisCli *redis.Client, rdb *databases.RDBInstance) *PodResourcesService {
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

type syncSignal struct {
	clusterKey string
}

// BeforWatchNewCluster called before watch events
func (cb *PodResourcesService) BeforeWatchNewCluster(ctx context.Context, clusterName string, resyncInterval time.Duration) assets.ClusterCallback {
	logging.Get().Info().Msgf("service assets before watch new cluster %s called.", clusterName)

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
				logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
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
			logging.Get().Info().Msg("start to consume pods")
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

			cnt, err := dal.CountResources(context.Background(), cb.parent.rdb.GetReadDB(), dal.ResourcesQuery().WithCluster(cb.cluster).WithNamespace(pod.Namespace).WithResourceKind(assets.KindDeployment).WithResourceName(ownerOwnerName))
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
			logging.Get().Error().Msgf("Panic when do on pod (%s) event: %v. event: %+v", podName, r, e)
			err = errors.New("panic")
		}
	}()

	tctx, cancel := context.WithTimeout(ctx, 8000*time.Millisecond)
	defer cancel()

	switch e.action {
	case assets.ActionDelete:
		rerr := dal.DeletePodResourceRelationInRDB(tctx, cb.parent.rdb.Get(), e.pod.Cluster, e.pod.Namespace, e.pod.Name)
		if rerr != nil {
			logging.Get().Err(rerr).Msg("delete pod resource rel in rdb error")
		}
	case assets.ActionUpdate, assets.ActionAdd:
		rerr := dal.UpsertPodResourceRelationInRDB(tctx, cb.parent.rdb.Get(), e.pod.Pod, e.pod.Owner.Name, e.pod.Owner.Kind, e.pod.Cluster, e.updateTime)
		if rerr != nil {
			logging.Get().Err(rerr).Msg("upsert pod resource rel in rdb error")
		}
	}
	return nil
}

func (cb *PodResourcesClusterCallback) OnTensorPod(pod *assets.TensorPod, action assets.AssetsAction) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if pod == nil {
		return errors.New("not given  pod")
	}
	return cb.sendInput(ctx, podEvent{
		pod:        pod,
		action:     action,
		updateTime: time.Now(),
	})
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
func (cb *PodResourcesClusterCallback) AfterDataSynced(ctx context.Context, dataSynced bool, clusterKey string) {
	if dataSynced {
		cb.inputQueue.Add(syncSignal{clusterKey: clusterKey})
	}
}

func (cb *PodResourcesClusterCallback) removeInactiveData(ctx context.Context, clusterKey string) error {
	return dal.CleanUpPodResourceRelationsInRDB(ctx, cb.parent.rdb.Get(), cb.refreshTime(), clusterKey)
}

func (cb *PodResourcesClusterCallback) OnHoneyspot(honeyspot *assets.TensorHoneySpot, action assets.AssetsAction) error {
	return nil
}

func (cb *PodResourcesClusterCallback) OnTensorRole(tensorRole *assets.TensorRole, action assets.AssetsAction) error {
	return nil
}

func (cb *PodResourcesClusterCallback) OnTensorClusterRole(tensorRole *assets.TensorClusterRole, action assets.AssetsAction) error {
	return nil
}

func (cb *PodResourcesClusterCallback) OnTensorNamespace(namespace *assets.TensorNamespace, action assets.AssetsAction) error {
	return nil
}

func (cb *PodResourcesClusterCallback) OnTensorNode(node *assets.TensorNode, action assets.AssetsAction) error {
	return nil
}

func (cb *PodResourcesClusterCallback) Name() string {
	return cb.parent.Name()
}

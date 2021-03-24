package assets

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/mgo.v2/bson"
	corev1 "k8s.io/api/core/v1"
)

var (
	saSingleton *ServiceAssetsService
	saInitOnce  sync.Once
)

func InitAndGetServiceAssetsService(mongo *mongo.Database) (*ServiceAssetsService, error) {
	if mongo == nil {
		return nil, errors.New("no mongoDB given to init serviceAssetsService")
	}
	saInitOnce.Do(func() {
		saSingleton = newServiceAssetsService(mongo)
	})
	return saSingleton, nil
}

func GetServiceAssetsService() (*ServiceAssetsService, bool) {
	return saSingleton, saSingleton != nil
}

type ServiceAssetsService struct {
	sync.RWMutex

	mongoDB *mongo.Database

	psCache *assets.PodServiceCache

	syncedClusters map[string]struct{}
}

type ServiceAssetsClusterCallback struct {
	cluster          string
	parent           *ServiceAssetsService
	refreshTimestamp int64
}

func newServiceAssetsService(mongo *mongo.Database) *ServiceAssetsService {
	return &ServiceAssetsService{
		mongoDB:        mongo,
		psCache:        assets.NewPodServiceCache(),
		syncedClusters: make(map[string]struct{}, 1),
	}
}

func (cb *ServiceAssetsService) setClusterDataSynced(cluster string) {
	cb.Lock()
	defer cb.Unlock()

	cb.syncedClusters[cluster] = struct{}{}
}

func (cb *ServiceAssetsService) IsClusterSynced(cluster string) bool {
	cb.RLock()
	defer cb.RUnlock()

	_, exist := cb.syncedClusters[cluster]
	return exist
}

// BeforWatchNewCluster called before watch events
func (cb *ServiceAssetsService) BeforWatchNewCluster(ctx context.Context, clusterName string) assets.ClusterCallback {
	logging.GetLogger().Info().Msgf("service assets before watch new cluster %s called.", clusterName)

	return &ServiceAssetsClusterCallback{
		cluster:          clusterName,
		parent:           cb,
		refreshTimestamp: time.Now().Unix(),
	}
}

func (cb *ServiceAssetsService) GetServiceInfoOfPod(cluster, podUID string) (sinfo *assets.ServiceInfo, ok bool) {
	sinfo, ok = cb.psCache.GetServiceInfoBy(cluster, podUID)
	if !ok || sinfo == nil {
		ok = false
		return
	}
	return sinfo, true
}

// Name returns the name
func (cb *ServiceAssetsService) Name() string {
	return "serviceAssets"
}

func (cb *ServiceAssetsClusterCallback) refreshUnixTimestamp() int64 {
	return atomic.LoadInt64(&cb.refreshTimestamp)
}

func (cb *ServiceAssetsClusterCallback) refreshTime() time.Time {
	return time.Unix(cb.refreshUnixTimestamp(), 0)
}

func (cb *ServiceAssetsClusterCallback) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	// update mongo storage if there are no service from endpoints.
	err := assets.OnPodEventForService(cb.parent.mongoDB, cb.cluster, newPod, oldPod, action)

	cerr := cb.parent.psCache.OnPodForServiceEvent(cb.cluster, newPod, oldPod, action)

	if cerr != nil || err != nil {
		logging.GetLogger().Warn().Msgf("%s callback on pod event(cluster: %s) action: %s, storage err: %v. cache err: %v", cb.Name(), cb.cluster, action, err, cerr)
	}
	return nil
}
func (cb *ServiceAssetsClusterCallback) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	// update mongo storage if there are no service from endpoints.
	err := assets.OnServiceEvent(cb.parent.mongoDB, cb.cluster, newSvc, oldEvc, action)
	return err
}
func (cb *ServiceAssetsClusterCallback) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// update mongo storage
	err := assets.OnEndpointsEvent(cb.parent.mongoDB, cb.cluster, newEpt, oldEpt, action)

	// update memory cache
	cerr := cb.parent.psCache.OnEndpointsEvent(cb.cluster, newEpt, oldEpt, action)

	if cerr != nil || err != nil {
		logging.GetLogger().Warn().Msgf("%s callback on endpoint event(cluster: %s) action: %s, storage err: %v. cache err: %v", cb.Name(), cb.cluster, action, err, cerr)
	}
	return err
}
func (cb *ServiceAssetsClusterCallback) AfterDataSynced(ctx context.Context, dataSynced bool) {
	if dataSynced {
		cb.parent.setClusterDataSynced(cb.cluster)
	}
	// delete all inactive data
	cb.expireInactiveServiceEndpoints(ctx)
}

func (cb *ServiceAssetsClusterCallback) expireInactiveServiceEndpoints(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	filter := bson.M{
		"cluster":        cb.cluster,
		"lastUpdateTime": bson.M{"$lt": cb.refreshTime()},
	}
	_, err := cb.parent.mongoDB.Collection(model.ServiceCollection.String()).DeleteMany(ctx, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("delete service collections error for cluster %s", cb.cluster)
	}

	filter = bson.M{
		"cluster":   cb.cluster,
		"updatedAt": bson.M{"$lt": cb.refreshTime()},
	}

	_, err = cb.parent.mongoDB.Collection(model.TensorServiceCollection.String()).DeleteMany(ctx, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("delete Tensor service collections error for cluster %s", cb.cluster)
	}

}

func (cb *ServiceAssetsClusterCallback) Name() string {
	return cb.parent.Name()
}

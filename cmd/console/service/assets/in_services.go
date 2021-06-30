package assets

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gopkg.in/mgo.v2/bson"
	corev1 "k8s.io/api/core/v1"
)

func GetServiceAssetsService(ctx context.Context) (*ServiceAssetsService, bool) {
	return inSvcInstance, inSvcInstance != nil
}

type ServiceAssetsService struct {
	sync.RWMutex

	mongoDB *mongotools.DatabaseWrapper

	syncedClusters map[string]struct{}
}

type ServiceAssetsClusterCallback struct {
	cluster          string
	parent           *ServiceAssetsService
	refreshTimestamp int64
}

func newServiceAssetsService(mongo *mongotools.DatabaseWrapper) *ServiceAssetsService {
	return &ServiceAssetsService{
		mongoDB:        mongo,
		syncedClusters: make(map[string]struct{}, 1),
	}
}

func (cb *ServiceAssetsService) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch: {},
		// assets.Endpoints2Watch: {},
		assets.Services2Watch: {},
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

// Name returns the name
func (cb *ServiceAssetsService) Name() string {
	return "serviceAssets"
}

func (cb *ServiceAssetsClusterCallback) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
	// do nothing
	return nil
}

func (cb *ServiceAssetsClusterCallback) refreshUnixTimestamp() int64 {
	return atomic.LoadInt64(&cb.refreshTimestamp)
}

func (cb *ServiceAssetsClusterCallback) refreshTime() time.Time {
	return time.Unix(cb.refreshUnixTimestamp(), 0)
}

func (cb *ServiceAssetsClusterCallback) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	// update mongo storage if there are no service from endpoints.
	err := assets.OnPodEventForService(cb.parent.mongoDB.Get(), cb.cluster, newPod, oldPod, action)

	if err != nil {
		logging.GetLogger().Warn().Msgf("%s callback on pod event(cluster: %s) action: %s, storage err: %v. cache err: %v", cb.Name(), cb.cluster, action, err)
	}
	return nil
}
func (cb *ServiceAssetsClusterCallback) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	// update mongo storage if there are no service from endpoints.
	err := assets.OnServiceEvent(cb.parent.mongoDB.Get(), cb.cluster, newSvc, oldEvc, action)
	return err
}

func (cb *ServiceAssetsClusterCallback) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// update mongo storage
	err := assets.OnEndpointsEvent(cb.parent.mongoDB.Get(), cb.cluster, newEpt, oldEpt, action)

	if err != nil {
		logging.GetLogger().Warn().Msgf("%s callback on endpoint event(cluster: %s) action: %s, storage err: %v.", cb.Name(), cb.cluster, action, err)
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
	ctx, cancel := context.WithTimeout(ctx, time.Second*20)
	defer cancel()

	filter := bson.M{
		"cluster":                cb.cluster,
		"historicised_timestamp": bson.M{"$lt": cb.refreshTime()},
	}
	_, err := cb.parent.mongoDB.Get().Collection(model.PodServiceRelationCollection.String()).DeleteMany(ctx, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("delete pod service collections error for cluster %s", cb.cluster)
	}
	_, err = cb.parent.mongoDB.Get().Collection(model.PodOwnerRefRelationCollection.String()).DeleteMany(ctx, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("delete pod owner collections error for cluster %s", cb.cluster)
	}

	filter = bson.M{
		"cluster":   cb.cluster,
		"updatedAt": bson.M{"$lt": cb.refreshTime()},
	}

	_, err = cb.parent.mongoDB.Get().Collection(model.TensorServiceCollection.String()).DeleteMany(ctx, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("delete Tensor service collections error for cluster %s", cb.cluster)
	}

}

func (cb *ServiceAssetsClusterCallback) Name() string {
	return cb.parent.Name()
}

package assets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/mgo.v2/bson"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var defaultRefreshTime = time.Now().Add(-1 * time.Hour).Unix()
var (
	inResInstance *AssetsInResourcesService
	inSvcInstance *ServiceAssetsService
	once          sync.Once
)

func Init(mongo *mongotools.DatabaseWrapper, postgresDB *rdbtools.GormWrapper) error {
	var err error
	once.Do(func() {
		if mongo == nil || postgresDB == nil {
			err = errors.New("dependency is nil")
			return
		}
		inResInstance = newAssetsInResources(mongo, postgresDB)
		inSvcInstance = newServiceAssetsService(mongo)
	})
	return err
}

func GetAssetsInResourcesService(ctx context.Context) (*AssetsInResourcesService, bool) {
	return inResInstance, inResInstance != nil
}

type AssetsInResourcesService struct {
	sync.RWMutex

	mongoDB          *mongotools.DatabaseWrapper
	postgresDB       *rdbtools.GormWrapper
	clusterCallbacks map[string]*AssetsInResourcesClusterCallback
	syncedClusters   map[string]struct{}
}

type AssetsInResourcesClusterCallback struct {
	cluster          string
	parent           *AssetsInResourcesService
	refreshTimestamp int64

	rsToDeploymentCache *sync.Map // string(namespace/name) -> *metav1.OwnerReference
}

func newAssetsInResources(mongo *mongotools.DatabaseWrapper, postgresDB *rdbtools.GormWrapper) *AssetsInResourcesService {
	return &AssetsInResourcesService{
		mongoDB:          mongo,
		postgresDB:       postgresDB,
		clusterCallbacks: make(map[string]*AssetsInResourcesClusterCallback, 2),
		syncedClusters:   make(map[string]struct{}),
	}
}

func (cb *AssetsInResourcesService) WatchedTypes() map[assets.WatchedType]struct{} {
	return map[assets.WatchedType]struct{}{
		assets.Pods2Watch:            {},
		assets.TensorResources2Watch: {},
	}
}

func (cb *AssetsInResourcesService) ListCurrentOnlineVulnerabilities(ctx context.Context, cluster string, offset, limit int64, scannerUrl string) ([]OnlineVulnListItem, error) {
	refreshTimestamp, ok := cb.getClusterRefreshTimestamp(cluster)
	if !ok {
		refreshTimestamp = defaultRefreshTime
	}
	filter := bson.M{
		"$and": []bson.M{
			{"isDeleted": false},
			{"lastUpdateTime": bson.M{"$gt": refreshTimestamp}},
		},
	}

	findOptions := options.Find().SetMaxTime(time.Second * 5)

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*5)
	defer mongoCtxCancel()
	cursor, err := cb.mongoDB.Get().Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, filter, findOptions)
	if err != nil {
		return nil, apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get containers: %w", err))
	}
	defer func() {
		if err := cursor.Close(mongoCtx); err != nil {
			logging.GetLogger().Error().Err(err).Msg("When closing cursor, but ignoring.")
		}
	}()

	onlineVulns := make(map[string]*OnlineVulnListItem, 100)

	for cursor.Next(ctx) {
		var container model.AssetContainer
		err := cursor.Decode(&container)

		if err != nil {
			return nil, apperror.NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't decode document: %w", err))
		}

		// only care about Running containers in this view
		if container.State != "Running" {
			continue
		}
		if container.PodOwnerKind == "NoOwner" || container.PodOwnerKind == "Job" {
			// Job will cause possibly detail request failing to find the resource. NoOwner is the type of static pod; tempararily igonore
			continue
		}

		nodeType := model.NodeTypeOwnerRef

		var tmpLibrary string
		if strings.Contains(container.Image, "http") == false {
			lastIndex := strings.Index(container.Image, "/")
			if lastIndex == -1 {
				tmpLibrary = "https://" + container.Image
			} else {
				tmpLibrary = "https://" + container.Image[:lastIndex]
			}
		} else {
			lastIndex := strings.Index(container.Image, "/")
			if lastIndex == -1 {
				tmpLibrary = container.Image
			} else {
				tmpLibrary = container.Image[:lastIndex]
			}
		}
		tmpFullRepoName := container.Repository[strings.Index(container.Repository, "/")+1:]
		scannerApiUrl := scannerUrl + "/api/v1/scan/reportsBySimpleImageDetails/?" + "digest=" + container.Digest +
			"&full_repo_name=" + tmpFullRepoName + "&library=" + tmpLibrary + "&tag=" + container.Tag
		ownerStr := fmt.Sprintf(
			"%s/%s/%s",
			container.Namespace,
			container.PodResourceKind,
			container.PodResourceName,
		)

		if _, ok := onlineVulns[ownerStr]; !ok {
			onlineVulns[ownerStr] = &OnlineVulnListItem{
				Namespace:            container.Namespace,
				ResourceKind:         container.PodResourceKind,
				ResourceName:         container.PodResourceName,
				ServiceName:          container.PodResourceName,
				NodeType:             nodeType,
				RunningContainersSet: make(map[string]bool),
				RunningPodsSet:       make(map[string]bool),
				VulnerabilitiesSet:   make(map[string]model.VulnerabilityInfo),
				Images:               make(map[string]string),
			}
			onlineVulns[ownerStr].Images[container.Image] = scannerApiUrl
		} else {
			onlineVulns[ownerStr].Images[container.Image] = scannerApiUrl
		}
		vulns := []model.VulnerabilityInfo{}

		containerNameDigest := fmt.Sprintf("%s:%s@%s", container.Name, container.Tag, container.Digest)
		onlineVulns[ownerStr].RunningContainersSet[containerNameDigest] = true
		onlineVulns[ownerStr].RunningPodsSet[container.PodName] = true
		for _, vuln := range vulns {
			onlineVulns[ownerStr].VulnerabilitiesSet[vuln.ID] = vuln
		}

	}
	var lock sync.Mutex
	start := time.Now()
	type tmpdata struct {
		Item model.SimpleImageDetail `json:"item"`
	}
	type tmpInfo struct {
		ApiVersion string  `json:"apiVersion"`
		Data       tmpdata `json:"data"`
	}
	for _, ov := range onlineVulns {
		runningContainers := []string{}
		for rcName := range ov.RunningContainersSet {
			runningContainers = append(runningContainers, rcName)
		}
		ov.RunningContainers = runningContainers

		runningPods := []string{}
		for rpName := range ov.RunningPodsSet {
			runningPods = append(runningPods, rpName)
		}
		ov.RunningPods = runningPods
		var wg sync.WaitGroup
		for _, v := range ov.Images {
			wg.Add(1)
			go func(v string) {
				defer wg.Done()
				resp, err := http.Get(v)
				if err != nil {
					return
				}
				resScanImage := tmpInfo{}
				err = json.NewDecoder(resp.Body).Decode(&resScanImage)
				resp.Body.Close()
				if err != nil {
					logging.GetLogger().Error().Err(err).Msg("风险探索 解析失败")
					resScanImage = tmpInfo{}
				}
				vulns := resScanImage.Data.Item.Vulnerabilities
				for _, vuln := range vulns {
					lock.Lock()
					ov.VulnerabilitiesSet[vuln.ID] = vuln
					lock.Unlock()
				}
			}(v)
		}
		wg.Wait()
		vulns := make([]model.VulnerabilityInfo, len(ov.VulnerabilitiesSet))

		i := 0
		for _, v := range ov.VulnerabilitiesSet {
			vulns[i] = v
			i = i + 1
		}

		util.SortVulnsBySeverityAndStuff(vulns, false)

		topVulnsNum := len(vulns)
		if len(vulns) >= 5 {
			topVulnsNum = 5
		}
		ov.TopVulns = vulns[:topVulnsNum]

		if len(ov.TopVulns) >= 1 {
			ov.OverallSeverity = vulns[0].Severity
		} else {
			ov.OverallSeverity = redclair.SeverityUnknown
		}
	}
	logging.GetLogger().Info().Int64("go并发用时:%v毫秒\n", time.Since(start).Milliseconds())
	err = cursor.Err()
	if err != nil {
		return nil, apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Cursor error: %w", err))
	}

	onlineVulnsList := []OnlineVulnListItem{}
	for _, ov := range onlineVulns {
		onlineVulnsList = append(onlineVulnsList, *ov)
	}

	cb.sortVulnListItemByOverallSeverity(onlineVulnsList, true)

	return onlineVulnsList, nil
}

func (cb *AssetsInResourcesService) GetOnlineVulnerabilityDetails(ctx context.Context, cluster, namespace, resourceKind, resourceName string, scannerUrl string) (*OnlineVulnDetails, error) {
	type tmpdata struct {
		Item model.SimpleImageDetail `json:"item"`
	}
	type tmpInfo struct {
		ApiVersion string  `json:"apiVersion"`
		Data       tmpdata `json:"data"`
	}
	filter := bson.M{
		"$and": []bson.M{
			{"isDeleted": false},
			{"namespace": namespace},
			{"podResourceKind": resourceKind},
			{"podResourceName": resourceName},
		},
	}

	findOptions := options.Find().SetMaxTime(time.Second * 1)
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*1)
	defer mongoCtxCancel()
	cursor, err := cb.mongoDB.Get().Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, filter, findOptions)
	if err != nil {
		return nil, apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get containers: %w", err))
	}
	defer func() {
		if err := cursor.Close(ctx); err != nil {
			logging.GetLogger().Error().Err(err).Msg("When closing cursor, but ignoring.")
		}
	}()

	ovDetails := OnlineVulnDetails{
		Namespace:    namespace,
		ResourceKind: resourceKind,
		ResourceName: resourceName,
		Containers:   make(map[string]OnlineVulnDetailsContainer),
	}

	foundAny := false
	for cursor.Next(ctx) {
		foundAny = true

		var container model.AssetContainer
		err := cursor.Decode(&container)
		if err != nil {
			return nil, apperror.NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't decode document: %w", err))
		}

		nameDigest := fmt.Sprintf("%s@%s", container.Name, container.Digest)
		var tmpLibrary string
		if strings.Contains(container.Image, "http") == false {
			lastIndex := strings.Index(container.Image, "/")
			if lastIndex == -1 {
				tmpLibrary = "https://" + container.Image
			} else {
				tmpLibrary = "https://" + container.Image[:lastIndex]
			}
		} else {
			lastIndex := strings.Index(container.Image, "/")
			if lastIndex == -1 {
				tmpLibrary = container.Image
			} else {
				tmpLibrary = container.Image[:lastIndex]
			}
		}
		tmpFullRepoName := container.Repository[strings.Index(container.Repository, "/")+1:]
		resp, err := http.Get(scannerUrl + "/api/v1/scan/reportsBySimpleImageDetails/?" + "digest=" + container.Digest +
			"&full_repo_name=" + tmpFullRepoName + "&library=" + tmpLibrary + "&tag=" + container.Tag)
		if err != nil {
			continue
		}
		resScanImage := tmpInfo{}
		err = json.NewDecoder(resp.Body).Decode(&resScanImage)
		resp.Body.Close()
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("风险探索详情 解析失败")
			resScanImage = tmpInfo{}
		}
		if _, ok := ovDetails.Containers[nameDigest]; !ok {
			ovDetails.Containers[nameDigest] = OnlineVulnDetailsContainer{
				Name:                container.Name,
				Repository:          container.Repository,
				Tag:                 container.Tag,
				Digest:              container.Digest,
				InstancesRunning:    &[]OnlineVulnDetailsContainerInstance{},
				InstancesWaiting:    &[]OnlineVulnDetailsContainerInstance{},
				InstancesTerminated: &[]OnlineVulnDetailsContainerInstance{},
				Vulnerabilities:     resScanImage.Data.Item.Vulnerabilities,
				SensitiveFiles:      resScanImage.Data.Item.Sensitives,
				WasScanned:          container.WasScanned,
				HarborURL:           container.HarborURL,
				TaskID:              container.TaskID,
			}
		}

		ovInstance := OnlineVulnDetailsContainerInstance{
			PodName:         container.PodName,
			Node:            container.Node,
			SeccompProfile:  container.SeccompProfile,
			DriftPrevention: container.DriftPrevention,
		}

		if container.State == "Terminated" {
			*(ovDetails.Containers[nameDigest].InstancesTerminated) = append(*(ovDetails.Containers[nameDigest].InstancesTerminated), ovInstance)
		} else if container.State == "Running" {
			*(ovDetails.Containers[nameDigest].InstancesRunning) = append(*(ovDetails.Containers[nameDigest].InstancesRunning), ovInstance)
		} else {
			*(ovDetails.Containers[nameDigest].InstancesWaiting) = append(*(ovDetails.Containers[nameDigest].InstancesWaiting), ovInstance)
		}
	}

	for k := range ovDetails.Containers {
		for i := range ovDetails.Containers[k].SensitiveFiles {
			if lang.Language(ctx) == lang.LanguageZH {
				description := ovDetails.Containers[k].SensitiveFiles[i].DescriptionZh
				ovDetails.Containers[k].SensitiveFiles[i].Description = description
			} else {
				description := ovDetails.Containers[k].SensitiveFiles[i].DescriptionEn
				ovDetails.Containers[k].SensitiveFiles[i].Description = description
			}
		}
	}

	err = cursor.Err()
	if err != nil {
		return nil, apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Cursor error: %w", err))
	}

	if !foundAny {
		return nil, apperror.NewMongoError(http.StatusNotFound,
			fmt.Errorf("Such resource has no containers"))
	}

	return &ovDetails, nil
}

func (cb *AssetsInResourcesService) sortVulnListItemByOverallSeverity(onlineVulnsList []OnlineVulnListItem, asc bool) {
	sort.Slice(onlineVulnsList, func(i, j int) bool {
		if !asc {
			i, j = j, i
		}
		return onlineVulnsList[i].OverallSeverity < onlineVulnsList[j].OverallSeverity
	})
}
func (cb *AssetsInResourcesService) setClusterDataSynced(cluster string) {
	cb.Lock()
	defer cb.Unlock()

	cb.syncedClusters[cluster] = struct{}{}
}

func (cb *AssetsInResourcesService) getClusterRefreshTimestamp(clusterName string) (int64, bool) {
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
func (cb *AssetsInResourcesService) BeforWatchNewCluster(ctx context.Context, clusterName string) assets.ClusterCallback {
	logging.GetLogger().Info().Msgf("service assets before watch new cluster %s called.", clusterName)

	ccb := &AssetsInResourcesClusterCallback{
		cluster:             clusterName,
		parent:              cb,
		refreshTimestamp:    time.Now().Unix(),
		rsToDeploymentCache: new(sync.Map),
	}
	cb.Lock()
	defer cb.Unlock()
	cb.clusterCallbacks[clusterName] = ccb

	return ccb
}

// Name returns the name
func (cb *AssetsInResourcesService) Name() string {
	return "onlineVulns"
}

func (cb *AssetsInResourcesClusterCallback) refreshUnixTimestamp() int64 {
	return atomic.LoadInt64(&cb.refreshTimestamp)
}

func (cb *AssetsInResourcesClusterCallback) refreshTime() time.Time {
	return time.Unix(cb.refreshUnixTimestamp(), 0)
}

func (cb *AssetsInResourcesClusterCallback) getUpperOwnerOfPod(pod *corev1.Pod) (*metav1.OwnerReference, bool) {
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
func (cb *AssetsInResourcesClusterCallback) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	if action == assets.ActionDelete {
		if oldPod == nil {
			return errors.New("not given old pod")
		}
		owner, _ := cb.getUpperOwnerOfPod(oldPod)
		directOwner := metav1.GetControllerOf(oldPod)

		for _, container := range oldPod.Status.ContainerStatuses {
			assets.UpdateAsset(cb.parent.mongoDB, cb.parent.postgresDB, cb.cluster, oldPod, &container, directOwner, owner, true)
		}
		assets.OnPodEventForResources(cb.parent.mongoDB.Get(), cb.cluster, newPod, oldPod, owner, action)
	} else if action == assets.ActionAdd || action == assets.ActionUpdate {
		if newPod == nil {
			return errors.New("not given new pod")
		}
		owner, _ := cb.getUpperOwnerOfPod(newPod)
		directOwner := metav1.GetControllerOf(newPod)

		for _, container := range newPod.Status.ContainerStatuses {
			assets.UpdateAsset(cb.parent.mongoDB, cb.parent.postgresDB, cb.cluster, newPod, &container, directOwner, owner, false)
		}
		assets.OnPodEventForResources(cb.parent.mongoDB.Get(), cb.cluster, newPod, oldPod, owner, action)
	}

	return nil
}

func (cb *AssetsInResourcesClusterCallback) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// ignore endpoint events
	return nil
}
func (cb *AssetsInResourcesClusterCallback) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	return nil
}

func (cb *AssetsInResourcesClusterCallback) removeReplicaSet(name string, namespace string) {
	cb.rsToDeploymentCache.Delete(getKeyFromRS(name, namespace))
}

func getKeyFromRS(name string, namespace string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func (cb *AssetsInResourcesClusterCallback) updateReplicaSet(rs *appsv1.ReplicaSet) {
	if rs == nil {
		return
	}
	controller := metav1.GetControllerOf(rs)
	if controller != nil {
		cb.rsToDeploymentCache.Store(getKeyFromRS(rs.Name, rs.Namespace), controller)
	}
}
func (cb *AssetsInResourcesClusterCallback) getOwnerRefOfRS(name string, namespace string) (*metav1.OwnerReference, bool) {
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

func (cb *AssetsInResourcesClusterCallback) OnTensorResourceEvent(newResource, oldResource *assets.TensorResource, action assets.AssetsAction) error {
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

func (cb *AssetsInResourcesClusterCallback) AfterDataSynced(ctx context.Context, dataSynced bool) {
	if dataSynced {
		cb.parent.setClusterDataSynced(cb.cluster)
	}

	// mark all inactive data
	cb.markInactiveAssetContainers(ctx)

}

func (cb *AssetsInResourcesClusterCallback) removeInactiveData(ctx context.Context) error {
	filter := bson.M{
		"cluster":                cb.cluster,
		"historicised_timestamp": bson.M{"$lt": cb.refreshTime()},
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second*20)
	defer cancel()
	_, err := cb.parent.mongoDB.Get().Collection(model.PodOwnerRefRelationCollection.String()).DeleteMany(ctx, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("delete pod owner collections error for cluster %s", cb.cluster)
	}
	return nil
}

// don't delete expired assets, for we can have the ability to trace
func (cb *AssetsInResourcesClusterCallback) markInactiveAssetContainers(ctx context.Context) error {
	// mark all entries that we didn't witness at the start of watcher as deleted.
	filter := bson.M{
		"isDeleted":      false,
		"lastUpdateTime": bson.M{"$lt": cb.refreshUnixTimestamp()},
	}
	monCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	update := bson.M{
		"$set": bson.M{
			"isDeleted":              true,
			"historicised_timestamp": time.Now(),
		},
	}
	_, err := cb.parent.mongoDB.Get().Collection(model.AssetsContainersCollection.String()).UpdateMany(monCtx, filter, update)
	if err != nil {
		return apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't get containers: %w", err))
	}

	return nil
}

func (cb *AssetsInResourcesClusterCallback) OnRoleEvent(newRole, oldRole *rbacv1.Role, action assets.AssetsAction) error {
	return nil
}
func (cb *AssetsInResourcesClusterCallback) OnClusterRoleEvent(newCRole, oldCRole *rbacv1.ClusterRole, action assets.AssetsAction) error {
	return nil
}
func (cb *AssetsInResourcesClusterCallback) OnRoleBindingEvent(newB, oldB *rbacv1.RoleBinding, action assets.AssetsAction) error {
	return nil
}
func (cb *AssetsInResourcesClusterCallback) OnClusterRoleBindingEvent(newB, oldB *rbacv1.ClusterRoleBinding, action assets.AssetsAction) error {
	return nil
}
func (cb *AssetsInResourcesClusterCallback) OnNamespaceEvent(newNs, oldNs *corev1.Namespace, action assets.AssetsAction) error {
	return nil
}
func (cb *AssetsInResourcesClusterCallback) OnServiceAccountEvent(newSa, oldSa *corev1.ServiceAccount, action assets.AssetsAction) error {
	return nil
}

func (cb *AssetsInResourcesClusterCallback) Name() string {
	return cb.parent.Name()
}

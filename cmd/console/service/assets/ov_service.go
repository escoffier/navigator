package assets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/mgo.v2/bson"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var defaultRefreshTime = time.Now().Add(-1 * time.Hour).Unix()

type OnlineVulnsService struct {
	sync.RWMutex

	mongoDB          *mongo.Database
	clusterCallbacks map[string]*OnlineVulnsClusterCallback
	syncedClusters   map[string]struct{}
}

type OnlineVulnsClusterCallback struct {
	cluster          string
	parent           *OnlineVulnsService
	refreshTimestamp int64
}

func NewOnlineVulnsService(mongo *mongo.Database) *OnlineVulnsService {
	return &OnlineVulnsService{
		mongoDB:          mongo,
		clusterCallbacks: make(map[string]*OnlineVulnsClusterCallback, 2),
		syncedClusters:   make(map[string]struct{}),
	}
}

func (cb *OnlineVulnsService) ListCurrentOnlineVulnerabilities(ctx context.Context, cluster string, offset, limit int64) ([]OnlineVulnListItem, error) {
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

	findOptions := options.Find().SetMaxTime(time.Second * 10)

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := cb.mongoDB.Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, filter, findOptions)
	if err != nil {
		return nil, apperror.NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get containers: %w", err))
	}
	defer func() {
		if err := cursor.Close(mongoCtx); err != nil {
			logging.GetLogger().Error().Err(err).Msg("When closing cursor, but ignoring.")
		}
	}()

	onlineVulns := make(map[string]*OnlineVulnListItem)

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

		services := []string{container.PodOwnerName}
		svcService, svcOk := GetServiceAssetsService()
		if svcOk {
			// TODO: This should be PodUid, not PodName
			sinfo, exist := svcService.GetServiceInfoOfPod(cluster, container.PodUID)
			if exist && sinfo != nil {
				if len(sinfo.Services()) > 0 {
					services = sinfo.Services()
				}
			}
		}

		for _, service := range services {
			ownerStr := fmt.Sprintf(
				"%s/%s/%s",
				container.Namespace,
				container.PodOwnerKind,
				service,
			)

			if _, ok := onlineVulns[ownerStr]; !ok {
				// TODO do we care about sensitive filenames in this
				onlineVulns[ownerStr] = &OnlineVulnListItem{
					Namespace:            container.Namespace,
					ResourceKind:         container.PodOwnerKind,
					ResourceName:         container.PodOwnerName,
					ServiceName:          service,
					RunningContainersSet: make(map[string]bool),
					RunningPodsSet:       make(map[string]bool),
					VulnerabilitiesSet:   make(map[string]model.VulnerabilityInfo),
				}
			}
			vulns := container.Vulnerabilities

			containerNameDigest := fmt.Sprintf("%s:%s@%s", container.Name, container.Tag, container.Digest)
			onlineVulns[ownerStr].RunningContainersSet[containerNameDigest] = true
			onlineVulns[ownerStr].RunningPodsSet[container.PodName] = true
			for _, vuln := range vulns {
				onlineVulns[ownerStr].VulnerabilitiesSet[vuln.ID] = vuln
			}
		}
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

func (cb *OnlineVulnsService) GetOnlineVulnerabilityDetails(ctx context.Context, cluster, namespace, resourceKind, resourceName string) (*OnlineVulnDetails, error) {
	filter := bson.M{
		"$and": []bson.M{
			{"isDeleted": false},
			{"namespace": namespace},
			{"podOwnerKind": resourceKind},
			{"podOwnerName": resourceName},
		},
	}

	if resourceKind == "service" {
		//get pod name
		podNameSlice, err := assets.GetPodNamesFromService(cb.mongoDB, cluster, namespace, resourceName)
		if err != nil {
			return nil, apperror.NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't get podName from service info : %w", err))
		}
		filter = bson.M{
			"isDeleted": false,
			"cluster":   cluster,
			"namespace": namespace,
			"podName":   bson.M{"$in": podNameSlice},
		}
	}

	findOptions := options.Find().SetMaxTime(time.Second * 10)
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := cb.mongoDB.Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, filter, findOptions)
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

		if _, ok := ovDetails.Containers[nameDigest]; !ok {
			ovDetails.Containers[nameDigest] = OnlineVulnDetailsContainer{
				Name:                container.Name,
				Repository:          container.Repository,
				Tag:                 container.Tag,
				Digest:              container.Digest,
				InstancesRunning:    &[]OnlineVulnDetailsContainerInstance{},
				InstancesWaiting:    &[]OnlineVulnDetailsContainerInstance{},
				InstancesTerminated: &[]OnlineVulnDetailsContainerInstance{},
				Vulnerabilities:     container.Vulnerabilities,
				SensitiveFiles:      container.SensitiveFiles,
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

func (cb *OnlineVulnsService) sortVulnListItemByOverallSeverity(onlineVulnsList []OnlineVulnListItem, asc bool) {
	sort.Slice(onlineVulnsList, func(i, j int) bool {
		if !asc {
			i, j = j, i
		}
		return onlineVulnsList[i].OverallSeverity < onlineVulnsList[j].OverallSeverity
	})
}
func (cb *OnlineVulnsService) setClusterDataSynced(cluster string) {
	cb.Lock()
	defer cb.Unlock()

	cb.syncedClusters[cluster] = struct{}{}
}

func (cb *OnlineVulnsService) getClusterRefreshTimestamp(clusterName string) (int64, bool) {
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
func (cb *OnlineVulnsService) BeforWatchNewCluster(ctx context.Context, clusterName string) assets.ClusterCallback {
	logging.GetLogger().Info().Msgf("service assets before watch new cluster %s called.", clusterName)

	ccb := &OnlineVulnsClusterCallback{
		cluster:          clusterName,
		parent:           cb,
		refreshTimestamp: time.Now().Unix(),
	}
	cb.Lock()
	defer cb.Unlock()
	cb.clusterCallbacks[clusterName] = ccb

	return ccb
}

// Name returns the name
func (cb *OnlineVulnsService) Name() string {
	return "onlineVulns"
}

func (cb *OnlineVulnsClusterCallback) refreshUnixTimestamp() int64 {
	return atomic.LoadInt64(&cb.refreshTimestamp)
}

func (cb *OnlineVulnsClusterCallback) refreshTime() time.Time {
	return time.Unix(cb.refreshUnixTimestamp(), 0)
}

func (cb *OnlineVulnsClusterCallback) OnPodEvent(newPod, oldPod *corev1.Pod, action assets.AssetsAction) error {
	if action == assets.ActionDelete {
		if oldPod == nil {
			return errors.New("not given old pod")
		}
		owner := metav1.GetControllerOf(oldPod)

		for _, container := range oldPod.Status.ContainerStatuses {
			assets.UpdateAsset(cb.parent.mongoDB, cb.cluster, oldPod, &container, owner, true)
		}
	} else if action == assets.ActionAdd || action == assets.ActionUpdate {
		if newPod == nil {
			return errors.New("not given new pod")
		}
		owner := metav1.GetControllerOf(newPod)

		// TODO: Do we care about InitContainer statuses?
		for _, container := range newPod.Status.ContainerStatuses {
			assets.UpdateAsset(cb.parent.mongoDB, cb.cluster, newPod, &container, owner, false)
		}
	}

	return nil
}
func (cb *OnlineVulnsClusterCallback) OnEndPointEvent(newEpt, oldEpt *corev1.Endpoints, action assets.AssetsAction) error {
	// ignore endpoint events
	return nil
}
func (cb *OnlineVulnsClusterCallback) OnServiceEvent(newSvc, oldEvc *corev1.Service, action assets.AssetsAction) error {
	return nil
}

func (cb *OnlineVulnsClusterCallback) AfterDataSynced(ctx context.Context, dataSynced bool) {
	if dataSynced {
		cb.parent.setClusterDataSynced(cb.cluster)
	}

	// mark all inactive data
	cb.markInactiveAssetContainers(ctx)
}

// don't delete expired assets, for we can have the ability to trace
func (cb *OnlineVulnsClusterCallback) markInactiveAssetContainers(ctx context.Context) (int, error) {
	var numMarked = 0
	err := cb.parent.mongoDB.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		// mark all entries that we didn't witness at the start of watcher as deleted.
		filter := bson.M{
			"isDeleted":      false,
			"lastUpdateTime": bson.M{"$lt": cb.refreshUnixTimestamp()},
		}

		findOptions := options.Find().SetMaxTime(time.Second * 10)
		var cursor *mongo.Cursor
		cursor, sessionError = cb.parent.mongoDB.Collection(model.AssetsContainersCollection.String()).Find(sessionContext, filter, findOptions)
		if sessionError != nil {
			return apperror.NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't get containers: %w", sessionError))
		}
		defer func() {
			if sessionError = cursor.Close(sessionContext); sessionError != nil {
				logging.GetLogger().Error().Err(sessionError).Msg("When closing cursor, but ignoring.")
			}
		}()

		for cursor.Next(sessionContext) {
			var container model.AssetContainer
			sessionError = cursor.Decode(&container)
			if sessionError != nil {
				return apperror.NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't decode document: %w", sessionError))
			}

			filter := bson.M{
				"$and": []bson.M{
					{"podName": container.PodName},
					{"name": container.Name},
				},
			}

			container.IsDeleted = true
			container.HistoricisedTimestamp = time.Now()

			update := bson.M{"$set": container}
			opts := options.Update().SetUpsert(true)

			_, sessionError = cb.parent.mongoDB.Collection(model.AssetsContainersCollection.String()).UpdateOne(sessionContext, filter, update, opts)
			if sessionError != nil {
				return apperror.NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Failed to upsert assetContainer to mongo: %w", sessionError))
			}

			numMarked++
		}

		sessionError = cursor.Err()
		if sessionError != nil {
			return apperror.NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Cursor error: %w", sessionError))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	return numMarked, nil
}

func (cb *OnlineVulnsClusterCallback) Name() string {
	return cb.parent.Name()
}

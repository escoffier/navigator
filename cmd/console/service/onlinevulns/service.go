package onlinevulns

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type OnlineVulnsService struct {
	mongodb *mongo.Database

	freshEntriesFromGuard sync.Mutex
	freshEntriesFrom      time.Time

	stopCh chan struct{}
}

func NewOnlineVulnsService(mongodb *mongo.Database) *OnlineVulnsService {
	res := &OnlineVulnsService{
		mongodb:          mongodb,
		stopCh:           make(chan struct{}),
		freshEntriesFrom: time.Now().Add(-1 * time.Hour * 24 * 7), // 1 week back by default, this will be changed fast if we have informer running
	}
	return res
}

// OnKubeConfigUpdate should be called e.g. when cluster modified or added
// When cluster deleted, set newClient to nil to stop any active informers.
func (r *OnlineVulnsService) OnKubeConfigUpdate(ctx context.Context, newClient *kubernetes.Clientset) error {
	return r.refreshInformer(ctx, newClient)
}

func (r *OnlineVulnsService) ListCurrentOnlineVulnerabilities(ctx context.Context, offset, limit int64) ([]onlineVulnListItem, error) {
	r.freshEntriesFromGuard.Lock()
	freshEntriesFromCp := r.freshEntriesFrom.Unix()
	r.freshEntriesFromGuard.Unlock()

	filter := bson.M{
		"$and": []bson.M{
			{"isDeleted": false},
			{"lastUpdateTime": bson.M{"$gt": freshEntriesFromCp}},
		},
	}

	findOptions := options.Find().SetMaxTime(time.Second * 10)

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := r.mongodb.Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, filter, findOptions)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get containers: %w", err))
	}
	defer func() {
		if err := cursor.Close(mongoCtx); err != nil {
			logging.GetLogger().Error().Err(err).Msg("When closing cursor, but ignoring.")
		}
	}()

	onlineVulns := make(map[string]*onlineVulnListItem)

	for cursor.Next(ctx) {
		var container model.AssetContainer
		err := cursor.Decode(&container)

		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't decode document: %w", err))
		}

		// only care about Running containers in this view
		if container.State != "Running" {
			continue
		}

		ownerStr := fmt.Sprintf(
			"%s/%s/%s",
			container.Namespace,
			container.PodOwnerKind,
			container.PodOwnerName,
		)

		if _, ok := onlineVulns[ownerStr]; !ok {
			// TODO do we care about sensitive filenames in this
			onlineVulns[ownerStr] = &onlineVulnListItem{
				Namespace:            container.Namespace,
				ResourceKind:         container.PodOwnerKind,
				ResourceName:         container.PodOwnerName,
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
		return nil, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Cursor error: %w", err))
	}

	onlineVulnsList := []onlineVulnListItem{}
	for _, ov := range onlineVulns {
		onlineVulnsList = append(onlineVulnsList, *ov)
	}

	r.sortVulnListItemByOverallSeverity(onlineVulnsList, true)

	return onlineVulnsList, nil
}

func (r *OnlineVulnsService) GetOnlineVulnerabilityDetails(ctx context.Context, namespace, resourceKind, resourceName string) (*onlineVulnDetails, error) {

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
		podNameSlice, err := assets.GetPodNameFromService(r.mongodb, namespace, resourceName)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't get podName from service info : %w", err))
		}
		filter = bson.M{
			"isDeleted": false,
			"namespace": namespace,
			"podName":   bson.D{{"$in", podNameSlice}},
		}
	}

	findOptions := options.Find().SetMaxTime(time.Second * 10)
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := r.mongodb.Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, filter, findOptions)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get containers: %w", err))
	}
	defer func() {
		if err := cursor.Close(ctx); err != nil {
			logging.GetLogger().Error().Err(err).Msg("When closing cursor, but ignoring.")
		}
	}()

	ovDetails := onlineVulnDetails{
		Namespace:    namespace,
		ResourceKind: resourceKind,
		ResourceName: resourceName,
		Containers:   make(map[string]onlineVulnDetailsContainer),
	}

	foundAny := false
	for cursor.Next(ctx) {
		foundAny = true

		var container model.AssetContainer
		err := cursor.Decode(&container)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't decode document: %w", err))
		}

		nameDigest := fmt.Sprintf("%s@%s", container.Name, container.Digest)

		if _, ok := ovDetails.Containers[nameDigest]; !ok {
			ovDetails.Containers[nameDigest] = onlineVulnDetailsContainer{
				Name:                container.Name,
				Repository:          container.Repository,
				Tag:                 container.Tag,
				Digest:              container.Digest,
				InstancesRunning:    &[]onlineVulnDetailsContainerInstance{},
				InstancesWaiting:    &[]onlineVulnDetailsContainerInstance{},
				InstancesTerminated: &[]onlineVulnDetailsContainerInstance{},
				Vulnerabilities:     container.Vulnerabilities,
				SensitiveFiles:      container.SensitiveFiles,
				WasScanned:          container.WasScanned,
				HarborURL:           container.HarborURL,
				TaskID:              container.TaskID,
			}
		}

		ovInstance := onlineVulnDetailsContainerInstance{
			PodName: container.PodName,
			Node:    container.Node,
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
		return nil, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Cursor error: %w", err))
	}

	if !foundAny {
		return nil, NewMongoError(http.StatusNotFound,
			fmt.Errorf("Such resource has no containers"))
	}

	return &ovDetails, nil
}

func (r *OnlineVulnsService) sortVulnListItemByOverallSeverity(onlineVulnsList []onlineVulnListItem, asc bool) {
	sort.Slice(onlineVulnsList, func(i, j int) bool {
		if !asc {
			i, j = j, i
		}
		return onlineVulnsList[i].OverallSeverity < onlineVulnsList[j].OverallSeverity
	})
}

func (r *OnlineVulnsService) refreshInformer(ctx context.Context, newClient *kubernetes.Clientset) error {

	logging.GetLogger().Info().Msg("Refreshing informer")

	if newClient == nil {
		logging.GetLogger().Info().Msg("Kubeclient nil, nothing to watch")
		return nil
	}

	logging.GetLogger().Info().Msg("Stopping current kubernetes informer")
	close(r.stopCh)

	// To consider: maybe it's better to watch StatefulSets, Deployments, ReplicaSets, Jobs, etc
	// instead of watching pods?
	// statefulsetInformer := informerFactory.Apps().V1().StatefulSets()

	informerFactory := informers.NewSharedInformerFactory(newClient, time.Minute*2)
	podInformer := informerFactory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
				return
			}
			r.onPodEvent(pod, false)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
				return
			}

			r.onPodEvent(pod, true)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Pod")
				return
			}
			r.onPodEvent(pod, false)
		},
	})
	r.removeAllServiceExpire()
	endPointsInformer := informerFactory.Core().V1().Endpoints().Informer()
	endPointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(newObj interface{}) {
			ept, ok := newObj.(*corev1.Endpoints)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Endpoints")
				return
			}
			r.onEptEvent(ept, false)
		},
		DeleteFunc: func(newObj interface{}) {
			ept, ok := newObj.(*corev1.Endpoints)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Endpoints")
				return
			}
			r.onEptEvent(ept, false)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ept, ok := newObj.(*corev1.Endpoints)
			if !ok {
				logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Endpoints")
				return
			}
			r.onEptEvent(ept, false)
		},
	})

	logging.GetLogger().Info().Msg("Starting kubernetes informer")

	// this must be done before startnig informer factory,
	// otherwise we may race with event when invalidating old entries.
	// This is because we will invalidate all entries with updatedAt before freshEntriesFrom.
	// New events will have updatedAt after freshEntriesFrom.
	r.freshEntriesFromGuard.Lock()
	r.freshEntriesFrom = time.Now()
	freshEntriesFromCp := r.freshEntriesFrom
	r.freshEntriesFromGuard.Unlock()

	// wait 1 more second before starting event gathering so I don't need to think about
	// whether mongo $lt and $gt are inclusive
	time.Sleep(time.Second * 1)

	r.stopCh = make(chan struct{})
	informerFactory.Start(r.stopCh)

	logging.GetLogger().Info().Msg("Waiting for kubernetes informer cache sync")

	var podType *corev1.Pod

	cacheSyncedCh := make(chan bool)
	go func() {
		cacheSynced := informerFactory.WaitForCacheSync(r.stopCh)[reflect.TypeOf(podType)]
		if !cacheSynced {
			logging.GetLogger().Error().Msg("Failed to sync cache")
			cacheSyncedCh <- false
		} else {
			cacheSyncedCh <- true
		}
	}()

	select {
	case syncedOk := <-cacheSyncedCh:
		if !syncedOk {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to sync informer cache"))
		}
	case <-time.After(time.Second * 120): // 2 minutes timeout for cache sync
		return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Informer cache resync timeout"))
	}

	go func() {
		for {
			if r.areAllFreshContainerEntriesAccountedFor(&podInformer) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
				defer cancel()
				numMarked, err := r.markStaleContainerEntriesAsDeleted(ctx, freshEntriesFromCp)
				if err != nil {
					logging.GetLogger().Warn().Err(err).Int("numMarked", numMarked).Msg("Failed to mark all old container entries as deleted. " +
						"This will lead to stale entries appearing upon service restart. This will be retried on next informer refresh. Ignoring for now.")
				} else {
					logging.GetLogger().Info().Int("numMarked", numMarked).Msg("Marked all old container entries as deleted.")
				}
				break
			}
			time.Sleep(time.Second * 5)
		}
	}()

	logging.GetLogger().Info().Int64("freshEntriesFromCp", freshEntriesFromCp.Unix()).Msg("Kubernetes informer cache synced")
	return nil
}

func (r *OnlineVulnsService) onEptEvent(ept *corev1.Endpoints, isDeleteEvent bool) {
	assets.UpdateEpt(r.mongodb, ept, isDeleteEvent)
}

func (r *OnlineVulnsService) onPodEvent(pod *corev1.Pod, isDeleteEvent bool) {
	owner := metav1.GetControllerOf(pod)

	// TODO: Do we care about InitContainer statuses?
	for _, container := range pod.Status.ContainerStatuses {
		assets.UpdateAsset(r.mongodb, pod, &container, owner, isDeleteEvent)
	}
}

func (r *OnlineVulnsService) areAllFreshContainerEntriesAccountedFor(informer *cache.SharedIndexInformer) bool {
	return (*informer).GetController().HasSynced() // Returns true once this controller has completed an initial resource listing
}

func (r *OnlineVulnsService) markStaleContainerEntriesAsDeleted(ctx context.Context, upTo time.Time) (int, error) {
	var numMarked = 0

	err := r.mongodb.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		// mark all entries that we didn't witness at the start of watcher as deleted.
		filter := bson.M{
			"lastUpdateTime": bson.M{"$lt": upTo.Unix()},
		}
		findOptions := options.Find().SetMaxTime(time.Second * 10)
		var cursor *mongo.Cursor
		cursor, sessionError = r.mongodb.Collection(model.AssetsContainersCollection.String()).Find(sessionContext, filter, findOptions)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError,
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
				return NewMongoError(http.StatusInternalServerError,
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

			_, sessionError = r.mongodb.Collection(model.AssetsContainersCollection.String()).UpdateOne(sessionContext, filter, update, opts)
			if sessionError != nil {
				return NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Failed to upsert assetContainer to mongo: %w", sessionError))
			}

			numMarked++
		}

		sessionError = cursor.Err()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Cursor error: %w", sessionError))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	return numMarked, nil
}
func (r *OnlineVulnsService) removeAllServiceExpire() {
	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()
	err := r.mongodb.Collection(model.ServiceCollection.String()).Drop(mongoCtx)
	if err != nil {
		logging.GetLogger().Info().Msg(fmt.Sprintf("delete endpoints collections   error：%+v \n", err))
	}
}

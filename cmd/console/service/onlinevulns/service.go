package onlinevulns

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

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

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := r.mongodb.Collection(model.AssetsContainerCollection).Find(mongoCtx, filter)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get containers: %w", err))
	}
	defer func() {
		if err := cursor.Close(ctx); err != nil {
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
			logging.GetLogger().Debug().Str("container", fmt.Sprintf("%s@%s", container.Name, container.Digest)).Msg("Not running.")
			continue
		}

		ownerStr := fmt.Sprintf("%s/%s", container.PodOwnerKind, container.PodOwnerName)

		if _, ok := onlineVulns[ownerStr]; !ok {
			onlineVulns[ownerStr] = &onlineVulnListItem{
				Namespace:            container.Namespace,
				ResourceKind:         container.PodOwnerKind,
				ResourceName:         container.PodOwnerName,
				RunningContainersSet: make(map[string]bool),
				RunningPodsSet:       make(map[string]bool),
				VulnerabilitiesSet:   make(map[string]redclair.VulnerabilityInfo),
			}
		}

		// TODO do we care about sensitive filenames in this
		scanTask, _, err := r.getScanTaskByDigest(ctx, container.Digest)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't get scan task by digest: %w", err))
		}

		vulns := scanTask.ScanReport.Vulns.Vulnerabilities

		containerNameDigest := fmt.Sprintf("%s:%s@%s", container.Name, container.Tag, container.Digest)
		onlineVulns[ownerStr].RunningContainersSet[containerNameDigest] = true
		onlineVulns[ownerStr].RunningPodsSet[container.PodName] = true
		for _, vuln := range vulns {
			onlineVulns[ownerStr].VulnerabilitiesSet[vuln.CVE] = vuln
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

		vulns := make([]redclair.VulnerabilityInfo, len(ov.VulnerabilitiesSet))
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

func (r *OnlineVulnsService) GetOnlineVulnerabilityDetails(ctx context.Context, resourceKind, resourceName string) (*onlineVulnDetails, error) {

	filter := bson.M{
		"$and": []bson.M{
			{"isDeleted": false},
			{"podOwnerKind": resourceKind},
			{"podOwnerName": resourceName},
		},
	}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := r.mongodb.Collection(model.AssetsContainerCollection).Find(mongoCtx, filter)
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
			scanTask, wasScanned, err := r.getScanTaskByDigest(ctx, container.Digest)
			if err != nil {
				return nil, NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't get scan task by digest: %w", err))
			}

			vulns := scanTask.ScanReport.Vulns.Vulnerabilities
			sensitives := scanTask.ScanReport.Vulns.Sensitives

			if !wasScanned && (len(vulns) > 0 || len(sensitives) > 0) {
				logging.GetLogger().Warn().Msg("We report that image wasn't scanned, but scan results are not empty. " +
					"Weird, check logic. Assuming it was scanned.")
				wasScanned = true
			}

			util.SortVulnsBySeverityAndStuff(vulns, false)

			ovDetails.Containers[nameDigest] = onlineVulnDetailsContainer{
				Name:                container.Name,
				Repository:          container.Repository,
				Tag:                 container.Tag,
				Digest:              container.Digest,
				InstancesRunning:    &[]onlineVulnDetailsContainerInstance{},
				InstancesWaiting:    &[]onlineVulnDetailsContainerInstance{},
				InstancesTerminated: &[]onlineVulnDetailsContainerInstance{},
				Vulnerabilities:     vulns,
				SensitiveFiles:      sensitives,
				WasScanned:          wasScanned,
				HarborURL:           scanTask.HarborURL,
				TaskID:              scanTask.ID,
			}

			ovDetails.Namespace = container.Namespace // all containers share namespace
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

func (r *OnlineVulnsService) getScanTaskByDigest(ctx context.Context, digest string) (model.ScanTask, bool, error) {
	filter := bson.M{
		"digest": digest,
	}

	// sort by finishedAt descending, so that we get the freshest scan result
	findOptions := options.FindOne()
	findOptions.SetSort(bson.D{{"finishedAt", -1}})

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	wasScanned := false

	singleResult := r.mongodb.Collection(model.ScanTasksCollection).FindOne(mongoCtx, filter, findOptions)
	if singleResult.Err() == mongo.ErrNoDocuments {
		// Maybe we haven't scanned this image yet, return no results, but indicate that we don't know
		return model.ScanTask{}, wasScanned, nil
	}

	if singleResult.Err() != nil {
		return model.ScanTask{}, wasScanned,
			NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find freshest scan: %w", singleResult.Err()))
	}

	wasScanned = true

	var scanTask model.ScanTask
	err := singleResult.Decode(&scanTask)
	if err != nil {
		return model.ScanTask{}, wasScanned,
			NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w", err))
	}

	return scanTask, wasScanned, nil
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

func (r *OnlineVulnsService) onPodEvent(pod *corev1.Pod, isDeleteEvent bool) {
	owner := metav1.GetControllerOf(pod)

	// TODO: Do we care about InitContainer statuses?
	for _, container := range pod.Status.ContainerStatuses {

		// image: 192.168.1.203:5000/tensorsec-console:latest
		repositoryTag := strings.Split(container.Image, ":")
		repository := strings.Join(repositoryTag[0:len(repositoryTag)-1], ":")
		tag := repositoryTag[len(repositoryTag)-1]

		// imageID: docker-pullable://192.168.1.203:5000/tensorsec-console@sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
		blablaShaDigest := strings.Split(container.ImageID, "@")
		shaDigest := blablaShaDigest[len(blablaShaDigest)-1]

		if shaDigest == "" {
			// Not sure why but it sometimes happens. Hopefully subsequent events sort this out.
			logging.GetLogger().Warn().Str("container", fmt.Sprintf("%+v", container.Name)).Msg("Container doesn't have digest. Skipping.")
			continue
		}

		state := "UnknownState"
		if container.State.Waiting != nil {
			state = "Waiting"
		} else if container.State.Running != nil {
			state = "Running"
		} else if container.State.Terminated != nil {
			state = "Terminated"
		}

		assetContainer := model.AssetContainer{
			IsDeleted:           isDeleteEvent,
			PodName:             pod.Name,
			Name:                container.Name,
			Repository:          repository,
			Tag:                 tag,
			Digest:              shaDigest,
			State:               state,
			Namespace:           pod.Namespace,
			Node:                pod.Spec.NodeName,
			ContainerID:         container.ContainerID, // containerID: docker://b503f2b9c3c693805312a888f875974f54fdd5f7d6d76de31d18ff12e958b4e1
			LastUpdateTimeEpoch: time.Now().Unix(),
		}

		if owner == nil {
			// owner can be nil e.g. when we run
			//kubectl run curl --image=radial/busyboxplus:curl -i --tty -n tensorsec
			assetContainer.PodOwnerKind = "NoOwner"
			assetContainer.PodOwnerName = pod.Name
		} else {
			assetContainer.PodOwnerKind = owner.Kind
			assetContainer.PodOwnerName = owner.Name
		}

		filter := bson.M{
			"$and": []bson.M{
				{"podName": assetContainer.PodName},
				{"name": assetContainer.Name},
			},
		}
		update := bson.M{"$set": assetContainer}
		opts := options.Update().SetUpsert(true)

		mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
		defer mongoCtxCancel()
		_, err := r.mongodb.Collection(model.AssetsContainerCollection).UpdateOne(mongoCtx, filter, update, opts)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetContainer)).Msg("Failed to upsert assetContainer to mongo")
		}
	}
}

func (r *OnlineVulnsService) areAllFreshContainerEntriesAccountedFor(informer *cache.SharedIndexInformer) bool {
	return (*informer).GetController().HasSynced() // Returns true once this controller has completed an initial resource listing
}

func (r *OnlineVulnsService) markStaleContainerEntriesAsDeleted(ctx context.Context, upTo time.Time) (int, error) {
	numMarked := 0

	// mark all entries that we didn't witness at the start of watcher as deleted.
	filter := bson.M{
		"lastUpdateTime": bson.M{"$lt": upTo.Unix()},
	}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := r.mongodb.Collection(model.AssetsContainerCollection).Find(mongoCtx, filter)
	if err != nil {
		return numMarked, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get containers: %w", err))
	}
	defer func() {
		if err := cursor.Close(ctx); err != nil {
			logging.GetLogger().Error().Err(err).Msg("When closing cursor, but ignoring.")
		}
	}()

	for cursor.Next(ctx) {
		var container model.AssetContainer
		err := cursor.Decode(&container)
		if err != nil {
			return numMarked, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't decode document: %w", err))
		}

		filter := bson.M{
			"$and": []bson.M{
				{"podName": container.PodName},
				{"name": container.Name},
			},
		}

		container.IsDeleted = true

		update := bson.M{"$set": container}
		opts := options.Update().SetUpsert(true)

		mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
		defer mongoCtxCancel()
		_, err = r.mongodb.Collection(model.AssetsContainerCollection).UpdateOne(mongoCtx, filter, update, opts)
		if err != nil {
			return numMarked, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Failed to upsert assetContainer to mongo: %w", err))
		}

		numMarked++
	}

	err = cursor.Err()
	if err != nil {
		return numMarked, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Cursor error: %w", err))
	}

	return numMarked, nil
}

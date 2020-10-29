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
	guard sync.Mutex

	mongodb *mongo.Database

	relistNow chan *kubernetes.Clientset
	relistErr chan error

	kubeClient     *kubernetes.Clientset
	discoveredFrom time.Time
	stopCh         chan struct{}
}

func NewOnlineVulnsService(mongodb *mongo.Database) *OnlineVulnsService {
	res := &OnlineVulnsService{
		mongodb:   mongodb,
		relistNow: make(chan *kubernetes.Clientset),
		relistErr: make(chan error),
		stopCh:    make(chan struct{}),
	}
	go res.informerRoutine()
	return res
}

// OnKubeConfigUpdate should be called e.g. when cluster modified or added
func (r *OnlineVulnsService) OnKubeConfigUpdate(ctx context.Context, newClient *kubernetes.Clientset) error {
	r.relistNow <- newClient
	err := <-r.relistErr
	return err
}

func (r *OnlineVulnsService) ListCurrentOnlineVulnerabilities(ctx context.Context, offset, limit int64) ([]onlineVulnListItem, error) {

	// we only consider events that we witnessed. Ignore previous events.
	// This is OK because when we start watcher, it sends events for all current pods.
	filter := bson.M{
		"lastUpdateTime": bson.M{"$gt": r.discoveredFrom.Unix()},
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
			logging.GetLogger().Info().Str("container", fmt.Sprintf("%s@%s", container.Name, container.Digest)).Msg("Not running.")
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
		vulns, _, _, err := r.getVulnsAndSensitivesByDigest(ctx, container.Digest)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't get vulnerability and sensitive filenames: %w", err))
		}

		containerNameDigest := fmt.Sprintf("%s@%s", container.Name, container.Digest)
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

		r.sortVulnsBySeverityAndStuff(vulns, true)

		topVulnsNum := len(vulns)
		if len(vulns) >= 5 {
			topVulnsNum = 5
		}
		ov.TopVulns = vulns[:topVulnsNum]

		if len(ov.TopVulns) >= 1 {
			ov.OverallSeverity = vulns[0].Severity
		} else {
			ov.OverallSeverity = "Unknown"
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
			vulns, sensitives, wasScanned, err := r.getVulnsAndSensitivesByDigest(ctx, container.Digest)
			if err != nil {
				return nil, NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Couldn't get vulnerability and sensitive filenames: %w", err))
			}

			if !wasScanned && (len(vulns) > 0 || len(sensitives) > 0) {
				logging.GetLogger().Warn().Msg("We report that image wasn't scanned, but scan results are not empty. " +
					"Weird, check logic. Assuming it was scanned.")
				wasScanned = true
			}

			r.sortVulnsBySeverityAndStuff(vulns, true)

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

func (r *OnlineVulnsService) getVulnsAndSensitivesByDigest(ctx context.Context, digest string) ([]redclair.VulnerabilityInfo, []redclair.Sensitive, bool, error) {
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
		return []redclair.VulnerabilityInfo{}, []redclair.Sensitive{}, wasScanned, nil
	}

	if singleResult.Err() != nil {
		return []redclair.VulnerabilityInfo{}, []redclair.Sensitive{}, wasScanned,
			NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find freshest scan: %w", singleResult.Err()))
	}

	wasScanned = true

	var scanTask model.ScanTask
	err := singleResult.Decode(&scanTask)
	if err != nil {
		return []redclair.VulnerabilityInfo{}, []redclair.Sensitive{}, wasScanned,
			NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w", err))
	}

	return scanTask.ScanReport.Vulns.Vulnerabilities, scanTask.ScanReport.Vulns.Sensitives, wasScanned, nil
}

func (r *OnlineVulnsService) sortVulnsBySeverityAndStuff(vulnerabilities []redclair.VulnerabilityInfo, asc bool) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if !asc {
			i, j = j, i
		}

		if redclair.SeverityMap[vulnerabilities[i].Severity] < redclair.SeverityMap[vulnerabilities[j].Severity] {
			return true
		} else if redclair.SeverityMap[vulnerabilities[i].Severity] > redclair.SeverityMap[vulnerabilities[j].Severity] {
			return false
		}

		if vulnerabilities[i].CVE < vulnerabilities[j].CVE {
			return true
		} else if vulnerabilities[i].CVE > vulnerabilities[j].CVE {
			return false
		}
		return false
	})
}

func (r *OnlineVulnsService) sortVulnListItemByOverallSeverity(onlineVulnsList []onlineVulnListItem, asc bool) {
	sort.Slice(onlineVulnsList, func(i, j int) bool {
		if !asc {
			i, j = j, i
		}
		return onlineVulnsList[i].OverallSeverity < onlineVulnsList[j].OverallSeverity
	})
}

func (r *OnlineVulnsService) informerRoutine() error {
	for {
		func() {
			select {
			case newClient := <-r.relistNow:
				r.kubeClient = newClient
				logging.GetLogger().Info().Msg("Restarting informer because of new kubeClient")
			case <-time.After(time.Minute * 10):
				logging.GetLogger().Info().Msg("Restarting informer to refresh resource list")
			}

			r.guard.Lock()
			defer r.guard.Unlock()

			if r.kubeClient == nil {
				logging.GetLogger().Info().Msg("Kubeclient nil, nothing to watch")
				r.relistErr <- nil
				return
			}

			logging.GetLogger().Info().Msg("Stopping current kubernetes informer")
			close(r.stopCh)

			// To consider: maybe it's better to watch StatefulSets, Deployments, ReplicaSets, Jobs, etc
			// instead of watching pods?
			// statefulsetInformer := informerFactory.Apps().V1().StatefulSets()
			informerFactory := informers.NewSharedInformerFactory(r.kubeClient, time.Second*30)
			podInformer := informerFactory.Core().V1().Pods().Informer()

			podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					pod, ok := obj.(*corev1.Pod)
					if !ok {
						logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
						return
					}

					// logging.GetLogger().Info().
					// 	Str("pod", fmt.Sprintf("%+v", pod)).
					// 	Msg("Add event.")

					r.onPodEvent(pod)
				},
				DeleteFunc: func(obj interface{}) {
					pod, ok := obj.(*corev1.Pod)
					if !ok {
						logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", obj)).Msg("Failed to cast to *corev1.Pod")
						return
					}

					// logging.GetLogger().Info().
					// 	Str("pod", fmt.Sprintf("%+v", pod)).
					// 	Msg("Delete event.")

					r.onPodEvent(pod)
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					pod, ok := newObj.(*corev1.Pod)
					if !ok {
						logging.GetLogger().Error().Str("obj-type", fmt.Sprintf("%T", newObj)).Msg("Failed to cast to *corev1.Pod")
						return
					}

					// logging.GetLogger().Info().
					// 	Str("pod", fmt.Sprintf("%+v", pod)).
					// 	Msg("Update event.")

					r.onPodEvent(pod)
				},
			})

			logging.GetLogger().Info().Msg("Starting kubernetes informer")

			r.discoveredFrom = time.Now()

			r.stopCh = make(chan struct{})
			informerFactory.Start(r.stopCh)

			logging.GetLogger().Info().Msg("Waiting for kubernetes informer cache sync")

			var podType *corev1.Pod

			// TODO add timeout for this.

			cacheSynced := informerFactory.WaitForCacheSync(r.stopCh)[reflect.TypeOf(podType)]
			if !cacheSynced {
				logging.GetLogger().Error().Msg("Failed to sync cache")
				r.relistErr <- NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to sync relister informer cache"))
				return
			}

			logging.GetLogger().Info().Int64("r.discoveredFrom", r.discoveredFrom.Unix()).Msg("Kubernetes informer cache synced")
			r.relistErr <- nil
		}()
	}
}

func (r *OnlineVulnsService) onPodEvent(pod *corev1.Pod) {
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
			logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetContainer)).Msg("Failed to insert assetContainer to mongo")
		}
	}
}

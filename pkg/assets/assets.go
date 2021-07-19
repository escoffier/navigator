package assets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func FindContainerByImageDigest(ctx context.Context, mongodb *mongo.Database, shaDigest string) (*model.AssetContainer, error) {
	filter := bson.M{
		"$and": []bson.M{
			{"digest": shaDigest},
			{"isDeleted": false},
		},
	}
	findOptions := options.FindOne()

	findOptions.SetMaxTime(time.Second * 10)

	singleResult := mongodb.Collection(model.AssetsContainersCollection.String()).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return nil, NewAssetDoesntExistError(http.StatusInternalServerError, fmt.Errorf("No document found: %w", singleResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", singleResult.Err()))
	}
	var assetContainer model.AssetContainer
	err := singleResult.Decode(&assetContainer)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode asset container: %w", err))
	}

	return &assetContainer, err
}

func UpdateAssetScanningDetails(assetContainer *model.AssetContainer, scanTask *model.ScanTask) {
	assetContainer.WasScanned = true

	assetContainer.HarborURL = scanTask.HarborURL
	assetContainer.SensitiveFiles = scanTask.ScanReport.Vulns.Sensitives
	assetContainer.Vulnerabilities = scanTask.ScanReport.Vulns.Vulnerabilities
	assetContainer.TaskID = scanTask.ID

	vulns := make([]model.VulnerabilityInfo, len(scanTask.ScanReport.Vulns.Vulnerabilities))

	topVulnsNum := len(scanTask.ScanReport.Vulns.Vulnerabilities)
	if len(vulns) >= 5 {
		topVulnsNum = 5
	}
	assetContainer.TopVulns = vulns[:topVulnsNum]

	if len(assetContainer.TopVulns) >= 1 {
		assetContainer.OverallSeverity = vulns[0].Severity
	} else {
		assetContainer.OverallSeverity = redclair.SeverityUnknown
	}
}

// owner is the direct owner of pod; resource is the inferenced owner, for the replicaset pod, it will infer to deployment
func UpdateAsset(mongodb *mongotools.DatabaseWrapper, postgresDB *rdbtools.GormWrapper, cluster string, pod *corev1.Pod, container *corev1.ContainerStatus, owner *metav1.OwnerReference, resource *metav1.OwnerReference, isDeleteEvent bool) {
	// image: 192.168.1.203:5000/tensorsec-console:latest
	repositoryTag := strings.Split(container.Image, ":")
	repository := strings.Join(repositoryTag[0:len(repositoryTag)-1], ":")
	tag := repositoryTag[len(repositoryTag)-1]

	// imageID: docker-pullable://192.168.1.203:5000/tensorsec-console@sha256:2166fca0902583220885c81e7dd194e51c05c2b58029c00d33b3c25a1448f108
	shaDigestAndPullInfo := strings.Split(container.ImageID, "@")
	shaDigest := shaDigestAndPullInfo[len(shaDigestAndPullInfo)-1]

	state := "UnknownState"
	if container.State.Waiting != nil {
		state = "Waiting"
	} else if container.State.Running != nil {
		state = "Running"
	} else if container.State.Terminated != nil {
		state = "Terminated"
	}

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer mongoCtxCancel()

	driftPrevention := ""
	seccompProfile := ""
	for k, v := range pod.Labels {
		if k == "tensorsec.driftprevent" {
			if v == "prevent" || v == "detect" {
				driftPrevention = v
			} else {
				driftPrevention = fmt.Sprintf("Invalid value, no effect: %s", v)
			}
		}
		if k == "tensorsec.seccompprotect" {
			seccompProfile = v
		}
	}

	//get pod container image
	Image := ""
	for _, c := range pod.Spec.Containers {
		if c.Name == container.Name {
			Image = c.Image
		}
	}

	assetContainer := model.AssetContainer{
		Cluster:             cluster,
		IsDeleted:           isDeleteEvent,
		PodName:             pod.Name,
		PodUID:              string(pod.UID),
		Name:                container.Name,
		Repository:          repository,
		Tag:                 tag,
		State:               state,
		Namespace:           pod.Namespace,
		Node:                pod.Spec.NodeName,
		ContainerID:         container.ContainerID, // containerID: docker://b503f2b9c3c693805312a888f875974f54fdd5f7d6d76de31d18ff12e958b4e1
		Image:               Image,
		LastUpdateTimeEpoch: time.Now().Unix(),
		DriftPrevention:     driftPrevention,
		SeccompProfile:      seccompProfile,
	}
	if shaDigest != "" {
		assetContainer.Digest = shaDigest

	}

	if isDeleteEvent {
		assetContainer.HistoricisedTimestamp = time.Now()
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
	if resource == nil {
		assetContainer.PodResourceName = pod.Name
		assetContainer.PodResourceKind = "NoOwner"
	} else {
		assetContainer.PodResourceName = resource.Name
		assetContainer.PodResourceKind = resource.Kind
	}
	filter := bson.M{
		"$and": []bson.M{
			{"podName": assetContainer.PodName},
			{"namespace": assetContainer.Namespace},
			{"name": assetContainer.Name},
		},
	}

	update := bson.M{"$set": assetContainer}

	opts := options.Update().SetUpsert(true)
	_, err := mongodb.Get().Collection(model.AssetsContainersCollection.String()).UpdateOne(mongoCtx, filter, update, opts)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetContainer)).Msg("Failed to upsert assetContainer to mongo")
	}

}

func getIPPort(ip string, port int32) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func OnPodEventForResources(mongodb *mongo.Database, kubeCluster string, newPod, oldPod *corev1.Pod, ownerRef *metav1.OwnerReference, action AssetsAction) error {
	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*2)
	defer mongoCtxCancel()

	if action == ActionDelete {
		if oldPod == nil {
			return errors.New("no old pods given")
		}

		filter := bson.M{
			"$and": []bson.M{
				{"cluster": kubeCluster},
				{"podUid": string(oldPod.UID)},
			},
		}
		_, err := mongodb.Collection(model.PodOwnerRefRelationCollection.String()).DeleteMany(mongoCtx, filter)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("delete PodOwnerRefRelationCollection error for pod event")
		}
	}
	if action == ActionUpdate || action == ActionAdd {
		if newPod == nil {
			return errors.New("no new pods given")
		}
		if newPod.UID == "" {
			return nil
		}

		ownerRefName := newPod.Name
		ownerRefKind := "NoOwner"
		if ownerRef != nil {
			ownerRefName = ownerRef.Name
			ownerRefKind = ownerRef.Kind
		}
		podOwnerRel := model.PodOwnerRefRelation{
			Namespace:    newPod.Namespace,
			OwnerRefName: ownerRefName,
			Cluster:      kubeCluster,
			OwnerRefKind: ownerRefKind,
			PodUID:       string(newPod.UID),
			PodName:      newPod.Name,
		}
		podOwnerRel.HistoricisedTimestamp = time.Now()

		filter := bson.M{
			"$and": []bson.M{
				{"cluster": kubeCluster},
				{"podUid": string(newPod.UID)},
			},
		}
		update := bson.M{
			"$set": podOwnerRel,
		}
		upOptions := options.Update().SetUpsert(true)
		_, upErr := mongodb.Collection(model.PodOwnerRefRelationCollection.String()).UpdateMany(mongoCtx, filter, update, upOptions)
		if upErr != nil {
			return upErr
		}
	}
	return nil
}

// GetPodNamesFromOwnerRef returns podname, resourceKind, and error if have.
func GetPodNamesFromOwnerRef(mongodb *mongo.Database, cluster, namespace, resName string) ([]string, string, error) {
	filter := bson.M{
		"$and": []bson.M{
			{"namespace": namespace},
			{"ownerRefName": resName},
			{"cluster": cluster},
		},
	}
	// from mongo

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(5 * time.Second)

	cur, err := mongodb.Collection(model.PodOwnerRefRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		return nil, "", NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find document: %w", err))
	}
	podsMap := make(map[string]struct{}, 10)
	kind := ""
	for cur.Next(mongoCtx) {
		var elem model.PodOwnerRefRelation
		err := cur.Decode(&elem)
		if err != nil {
			return nil, "", NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		podsMap[elem.PodName] = struct{}{}
		kind = elem.OwnerRefKind
	}
	podsSlice := make([]string, len(podsMap))
	i := 0
	for podName := range podsMap {
		podsSlice[i] = podName
		i++
	}
	return podsSlice, kind, nil
}

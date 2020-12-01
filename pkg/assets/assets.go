package assets

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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

	singleResult := mongodb.Collection(model.AssetsContainerCollection).FindOne(ctx, filter, findOptions)
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

func UpdateAssetScanningDetails(ctx context.Context, mongodb *mongo.Database, assetContainer *model.AssetContainer, scanTask *model.ScanTask) {
	assetContainer.WasScanned = true

	assetContainer.HarborURL = scanTask.HarborURL
	assetContainer.SensitiveFiles = scanTask.ScanReport.Vulns.Sensitives
	assetContainer.Vulnerabilities = scanTask.ScanReport.Vulns.Vulnerabilities
	assetContainer.TaskID = scanTask.ID

	vulns := make([]redclair.VulnerabilityInfo, len(scanTask.ScanReport.Vulns.Vulnerabilities))

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

func UpdateAsset(mongodb *mongo.Database, pod *corev1.Pod, container *corev1.ContainerStatus, owner *metav1.OwnerReference, isDeleteEvent bool) {
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

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()

	assetContainer := model.AssetContainer{
		IsDeleted:  isDeleteEvent,
		PodName:    pod.Name,
		Name:       container.Name,
		Repository: repository,
		Tag:        tag,
		State:               state,
		Namespace:           pod.Namespace,
		Node:                pod.Spec.NodeName,
		ContainerID:         container.ContainerID, // containerID: docker://b503f2b9c3c693805312a888f875974f54fdd5f7d6d76de31d18ff12e958b4e1
		LastUpdateTimeEpoch: time.Now().Unix(),
	}
	if shaDigest != "" {
		assetContainer.Digest = shaDigest
	}

	if shaDigest != "" {
		scanTask, wasScanned, err := getScanTaskByDigest(mongoCtx, mongodb, shaDigest)
		assetContainer.WasScanned = wasScanned
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetContainer)).Msg("Failed to get scanner task for image")
		}
		UpdateAssetScanningDetails(mongoCtx, mongodb, &assetContainer, &scanTask)
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

	filter := bson.M{
		"$and": []bson.M{
			{"podName": assetContainer.PodName},
			{"name": assetContainer.Name},
		},
	}

	update := bson.M{"$set": assetContainer}
	opts := options.Update().SetUpsert(true)

	_, err := mongodb.Collection(model.AssetsContainerCollection).UpdateOne(mongoCtx, filter, update, opts)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetContainer)).Msg("Failed to upsert assetContainer to mongo")
	}

}

func getScanTaskByDigest(ctx context.Context, mongodb *mongo.Database, digest string) (model.ScanTask, bool, error) {
	filter := bson.M{
		"$and": []bson.M{
			{"stale": false},
			{"status": model.ScanStatusSucceeded},
			{"digest": digest},
		},
	}

	findOptions := options.FindOne()

	findOptions.SetMaxTime(time.Second * 10)

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	wasScanned := false

	singleResult := mongodb.Collection(model.ScanTasksCollection).FindOne(mongoCtx, filter, findOptions)
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

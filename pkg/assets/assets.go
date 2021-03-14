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

func UpdateAssetScanningDetails(ctx context.Context, mongodb *mongo.Database, assetContainer *model.AssetContainer, scanTask *model.ScanTask) {
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

func UpdateAsset(mongodb *mongo.Database, cluster string, pod *corev1.Pod, container *corev1.ContainerStatus, owner *metav1.OwnerReference, isDeleteEvent bool) {
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
		Name:                container.Name,
		Repository:          repository,
		Tag:                 tag,
		State:               state,
		Namespace:           pod.Namespace,
		Node:                pod.Spec.NodeName,
		ContainerID:         container.ContainerID, // containerID: docker://b503f2b9c3c693805312a888f875974f54fdd5f7d6d76de31d18ff12e958b4e1
		Image:               Image,
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
			{"namespace": assetContainer.Namespace},
			{"name": assetContainer.Name},
		},
	}

	update := bson.M{"$set": assetContainer}
	opts := options.Update().SetUpsert(true)

	_, err := mongodb.Collection(model.AssetsContainersCollection.String()).UpdateOne(mongoCtx, filter, update, opts)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetContainer)).Msg("Failed to upsert assetContainer to mongo")
	}

}

func getIPPort(ip string, port int32) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func OnPodEventForService(mongodb *mongo.Database, kubeCluster string, newPod, oldPod *corev1.Pod, action AssetsAction) error {
	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*15)
	defer mongoCtxCancel()

	if action == ActionDelete {
		if oldPod == nil {
			return errors.New("no old pods given")
		}

		filter := bson.M{
			"$and": []bson.M{
				{"cluster": kubeCluster},
				{"namespace": oldPod.Namespace},
				{"podUid": string(oldPod.UID)},
			},
		}
		_, err := mongodb.Collection(model.ServiceCollection.String()).DeleteMany(mongoCtx, filter)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("delete service collection error for pod event")
		}
	}
	if action == ActionUpdate || action == ActionAdd {
		if newPod == nil {
			return errors.New("no new pods given")
		}
		if newPod.UID == "" {
			return nil
		}
		owner := metav1.GetControllerOf(newPod)
		svcName := newPod.Name
		svcKind := ""
		if owner != nil {
			svcName = owner.Name
			svcKind = owner.Kind
		}

		filter := bson.M{
			"$and": []bson.M{
				{"cluster": kubeCluster},
				{"namespace": newPod.Namespace},
				{"podUid": string(newPod.UID)},
			},
		}

		update := bson.M{
			"$set": bson.M{
				"kind": svcKind,
			},
		}

		// if exists, update its kind field; if not, insert.
		res, err := mongodb.Collection(model.ServiceCollection.String()).UpdateMany(mongoCtx, filter, update)
		if err == nil && res.MatchedCount >= 1 { // if the document exists for filter, we only update the kind.
			return nil
		}

		assetService := model.Service{
			Namespace: newPod.Namespace,
			Name:      svcName,
			Cluster:   kubeCluster,
			Type:      "byController",
			Kind:      svcKind,
			PodUID:    string(newPod.UID),
			PodName:   newPod.Name,
		}
		// There are possibly two types of services: created by controllers; or endpoints. We priorly prefer endpoints.
		_, insertErr := mongodb.Collection(model.ServiceCollection.String()).InsertOne(mongoCtx, assetService)
		if insertErr != nil {
			logging.GetLogger().Error().Err(insertErr).Str("asset", fmt.Sprintf("%+v", assetService)).Msg("Failed to insert service to mongo")
			return insertErr
		}

	}
	return nil
}

func OnServiceEvent(mongodb *mongo.Database, kubeCluster string, newSvc, oldSvc *corev1.Service, action AssetsAction) error {
	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*15)
	defer mongoCtxCancel()

	if action == ActionDelete {
		if oldSvc == nil {
			return errors.New("no old svc given")
		}

		filter := bson.M{
			"$and": []bson.M{
				{"cluster": kubeCluster},
				{"namespace": oldSvc.Namespace},
				{"serviceName": oldSvc.Name},
			},
		}
		_, err := mongodb.Collection(model.TensorServiceCollection.String()).DeleteMany(mongoCtx, filter)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("delete service collection error for pod event")
		}
	}
	if action == ActionUpdate || action == ActionAdd {
		if newSvc == nil {
			return errors.New("no new svc given")
		}

		filter := bson.M{
			"$and": []bson.M{
				{"cluster": kubeCluster},
				{"namespace": newSvc.Namespace},
				{"serviceName": newSvc.Name},
			},
		}

		assetService := model.TensorService{
			Namespace:   newSvc.Namespace,
			ServiceName: newSvc.Name,
			Cluster:     kubeCluster,
			Selectors:   newSvc.Spec.Selector,
			UpdatedAt:   time.Now().Unix(),
		}
		if action == ActionAdd {
			assetService.CreatedAt = time.Now().Unix()
		}
		// There are possibly two types of services: created by controllers; or endpoints. We priorly prefer endpoints.

		update := bson.M{"$set": assetService}
		opts := options.Update().SetUpsert(true)
		_, insertErr := mongodb.Collection(model.TensorServiceCollection.String()).UpdateOne(mongoCtx, filter, update, opts)

		if insertErr != nil {
			logging.GetLogger().Error().Err(insertErr).Str("asset", fmt.Sprintf("%+v", assetService)).Msg("Failed to insert service to mongo")
			return insertErr
		}

	}
	return nil
}

// OnEndpointsEvent updates the mongo according to the event
func OnEndpointsEvent(mongodb *mongo.Database, kubeCluster string, newEpt, oldEpt *corev1.Endpoints, action AssetsAction) error {
	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()

	if action == ActionDelete {
		if oldEpt == nil {
			return errors.New("no old endpoints given")
		}
		for _, v := range oldEpt.Subsets {
			for _, address := range v.Addresses {
				podUID := ""
				if address.TargetRef != nil {
					podUID = string(address.TargetRef.UID)
				}
				var filter bson.M
				if len(podUID) > 0 {
					filter = bson.M{
						"$and": []bson.M{
							{"cluster": kubeCluster},
							{"namespace": oldEpt.Namespace},
							{"name": oldEpt.Name},
							{"podUid": podUID},
						},
					}
				} else {
					filter = bson.M{
						"$and": []bson.M{
							{"cluster": kubeCluster},
							{"namespace": oldEpt.Namespace},
							{"name": oldEpt.Name},
							{"ip": address.IP},
						},
					}
				}

				_, err := mongodb.Collection(model.ServiceCollection.String()).DeleteMany(mongoCtx, filter)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", filter)).Msg("Failed to delete  EndPoints to mongo")
					return err
				}
			}
		}
	}

	if action == ActionAdd || action == ActionUpdate {
		if newEpt == nil {
			return errors.New("no new endpoints given")
		}
		assetService := model.Service{
			Namespace: newEpt.Namespace,
			Name:      newEpt.Name,
			Cluster:   kubeCluster,
			Type:      "byEndpoints",
		}
		assetService.HistoricisedTimestamp = time.Now()

		for _, v := range newEpt.Subsets {
			for _, address := range v.Addresses {
				assetService.IP = address.IP
				if address.TargetRef == nil {
					assetService.PodName = ""
					assetService.PodUID = ""
				} else {
					assetService.PodName = address.TargetRef.Name
					assetService.PodUID = string(address.TargetRef.UID)
				}

				var filter bson.M
				if len(assetService.PodUID) > 0 {
					filter = bson.M{
						"$and": []bson.M{
							{"cluster": kubeCluster},
							{"namespace": newEpt.Namespace},
							{"name": newEpt.Name},
							{"podUid": assetService.PodUID},
						},
					}
				} else {
					filter = bson.M{
						"$and": []bson.M{
							{"cluster": kubeCluster},
							{"namespace": newEpt.Namespace},
							{"name": newEpt.Name},
							{"ip": address.IP},
						},
					}
				}
				update := bson.M{"$set": assetService}
				opts := options.Update().SetUpsert(true)
				_, err := mongodb.Collection(model.ServiceCollection.String()).UpdateOne(mongoCtx, filter, update, opts)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetService)).Msg("Failed to upsert assetService to mongo")
					return err
				}
			}
		}
	}

	return nil
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

	singleResult := mongodb.Collection(model.ScanTasksCollection.String()).FindOne(mongoCtx, filter, findOptions)
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

func GetPodNamesFromService(mongodb *mongo.Database, cluster, namespace, snvName string) ([]string, error) {
	filter := bson.M{
		"$and": []bson.M{
			{"namespace": namespace},
			{"name": snvName},
			{"cluster": cluster},
		},
	}
	// from mongo

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(10 * time.Second)

	cur, err := mongodb.Collection(model.ServiceCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}
	podsMap := make(map[string]struct{}, 2)
	for cur.Next(mongoCtx) {
		var service model.Service
		err := cur.Decode(&service)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		podsMap[service.PodName] = struct{}{}
	}
	podsSlice := make([]string, len(podsMap))
	i := 0
	for podName := range podsMap {
		podsSlice[i] = podName
		i++
	}
	return podsSlice, nil
}

func GetResNameFromServiceRelation(mongodb *mongo.Database, namespace, snvName string) ([]string, error) {
	filter := bson.M{
		"namespace": namespace,
		"name":      snvName,
		"resName":   bson.D{{"$ne", ""}, {"$exists", true}},
	}
	// from mongo

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(10 * time.Second)

	cur, err := mongodb.Collection(model.ServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}
	ResNameSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var serviceRl model.ServiceRelation
		err := cur.Decode(&serviceRl)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		if serviceRl.ResName != "" {
			ResNameSlice = append(ResNameSlice, serviceRl.ResName)
		}
	}
	return ResNameSlice, nil
}

func GetFocusFromServiceRelation(mongodb *mongo.Database, namespace, snvName, username string) (bool, error) {

	filter := bson.M{
		"namespace": namespace,
		"name":      snvName,
		"focusName": username,
	}

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*2)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(10 * time.Second)

	cur, err := mongodb.Collection(model.ServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find document: %w", err))
		return false, err
	}
	for cur.Next(mongoCtx) {
		var serviceRl model.ServiceRelation
		err := cur.Decode(&serviceRl)
		if err != nil {
			return false, NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't decode document: %w", err))
		}
		if serviceRl.FocusName == username {
			return true, nil
		}
	}
	return false, nil

}

func GetServiceSha256Val(mongodb *mongo.Database, namespace, snvName string) ([]string, error) {

	filter := bson.M{
		"$and": []bson.M{
			{"namespace": namespace},
			{"name": snvName},
		},
	}
	// from mongo

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(10 * time.Second)

	cur, err := mongodb.Collection(model.ServiceCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}
	podNameSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var service model.Service
		err := cur.Decode(&service)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		podNameSlice = append(podNameSlice, service.PodName)
	}

	filter = bson.M{
		"isDeleted": false,
		"namespace": namespace,
		"podName":   bson.D{{"$in", podNameSlice}},
	}

	opts := options.Find()
	opts.SetMaxTime(time.Second * 10)

	coll := mongodb.Collection(model.AssetsContainersCollection.String())

	cur, err = coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find %s documents: %w", model.AssetsContainersCollection.String(), err))
	}
	defer cur.Close(mongoCtx)
	shaSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var container model.AssetContainer
		err := cur.Decode(&container)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		if container.Digest != "" {
			shaSlice = append(shaSlice, container.Digest)
		}
	}
	return shaSlice, nil

}

func GetServiceRepository(mongodb *mongo.Database, namespace, snvName string) ([]string, error) {

	filter := bson.M{
		"$and": []bson.M{
			{"namespace": namespace},
			{"name": snvName},
		},
	}
	// from mongo

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(10 * time.Second)

	cur, err := mongodb.Collection(model.ServiceCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}
	podNameSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var service model.Service
		err := cur.Decode(&service)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		podNameSlice = append(podNameSlice, service.PodName)
	}

	filter = bson.M{
		"isDeleted": false,
		"namespace": namespace,
		"podName":   bson.D{{"$in", podNameSlice}},
	}

	opts := options.Find()
	opts.SetMaxTime(time.Second * 10)

	coll := mongodb.Collection(model.AssetsContainersCollection.String())

	cur, err = coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find %s documents: %w", model.AssetsContainersCollection.String(), err))
	}
	defer cur.Close(mongoCtx)
	RepositorySlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var container model.AssetContainer
		err := cur.Decode(&container)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		if container.Digest != "" {
			RepositorySlice = append(RepositorySlice, container.Repository)
		}
	}
	return RepositorySlice, nil

}

func GetAliasName(mongodb *mongo.Database, namespace, snvName string) (string, error) {
	filter := bson.M{
		"namespace": namespace,
		"name":      snvName,
	}

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()
	opt := options.FindOne()
	opt.SetMaxTime(10 * time.Second)
	var alias model.ServiceAlias
	err := mongodb.Collection(model.ServiceAliasCollection.String()).FindOne(mongoCtx, filter, opt).Decode(&alias)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return "", err
	}

	return alias.AliasName, nil
}

func GetServiceImages(mongodb *mongo.Database, namespace, snvName string) ([]string, error) {

	filter := bson.M{
		"$and": []bson.M{
			{"namespace": namespace},
			{"name": snvName},
		},
	}
	// from mongo

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(10 * time.Second)

	cur, err := mongodb.Collection(model.ServiceCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}
	podNameSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var service model.Service
		err := cur.Decode(&service)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		podNameSlice = append(podNameSlice, service.PodName)
	}

	filter = bson.M{
		"isDeleted": false,
		"namespace": namespace,
		"podName":   bson.D{{"$in", podNameSlice}},
	}

	opts := options.Find()
	opts.SetMaxTime(time.Second * 10)

	coll := mongodb.Collection(model.AssetsContainersCollection.String())

	cur, err = coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find %s documents: %w", model.AssetsContainersCollection.String(), err))
	}
	defer cur.Close(mongoCtx)
	imageSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var container model.AssetContainer
		err := cur.Decode(&container)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		if container.Image != "" {
			imageSlice = append(imageSlice, container.Image)
		}
	}
	return imageSlice, nil

}

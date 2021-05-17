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

func UpdateAsset(mongodb *mongotools.DatabaseWrapper, postgresDB *rdbtools.GormWrapper, cluster string, pod *corev1.Pod, container *corev1.ContainerStatus, owner *metav1.OwnerReference, isDeleteEvent bool) {
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

	if shaDigest != "" {
		scanTask, wasScanned, err := getScanTaskByDigest(mongoCtx, mongodb, shaDigest)
		assetContainer.WasScanned = wasScanned
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetContainer)).Msg("Failed to get scanner task for image")
		}
		UpdateAssetScanningDetails(&assetContainer, &scanTask)
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
	_, err := mongodb.Get().Collection(model.AssetsContainersCollection.String()).UpdateOne(mongoCtx, filter, update, opts)
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
				{"podUid": string(oldPod.UID)},
			},
		}
		_, err := mongodb.Collection(model.PodOwnerRefRelationCollection.String()).DeleteMany(mongoCtx, filter)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("delete PodOwnerRefRelationCollection error for pod event")
		}
		_, err = mongodb.Collection(model.PodServiceRelationCollection.String()).DeleteMany(mongoCtx, filter)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("delete PodServiceRelationCollection error for pod event")
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
		ownerName := ""
		svcKind := ""
		if owner != nil {
			ownerName = owner.Name
			svcKind = owner.Kind
		} else {
			return errors.New("get owner error")
		}

		podOwnerRel := model.PodOwnerRefRelation{
			Namespace:    newPod.Namespace,
			OwnerRefName: ownerName,
			Cluster:      kubeCluster,
			OwnerRefKind: svcKind,
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

				_, err := mongodb.Collection(model.PodServiceRelationCollection.String()).DeleteMany(mongoCtx, filter)
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
		podSvcRel := model.PodServiceRelation{
			Namespace: newEpt.Namespace,
			Name:      newEpt.Name,
			Cluster:   kubeCluster,
		}
		podSvcRel.HistoricisedTimestamp = time.Now()

		for _, v := range newEpt.Subsets {
			for _, address := range v.Addresses {
				podSvcRel.IP = address.IP
				if address.TargetRef == nil {
					podSvcRel.PodName = ""
					podSvcRel.PodUID = ""
				} else {
					podSvcRel.PodName = address.TargetRef.Name
					podSvcRel.PodUID = string(address.TargetRef.UID)
				}

				var filter bson.M
				if len(podSvcRel.PodUID) > 0 {
					filter = bson.M{
						"$and": []bson.M{
							{"cluster": kubeCluster},
							{"namespace": newEpt.Namespace},
							{"name": newEpt.Name},
							{"podUid": podSvcRel.PodUID},
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

				update := bson.M{"$set": podSvcRel}
				opts := options.Update().SetUpsert(true)
				_, err := mongodb.Collection(model.PodServiceRelationCollection.String()).UpdateMany(mongoCtx, filter, update, opts)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", podSvcRel)).Msg("Failed to upsert assetService to mongo")
					return err
				}
			}
		}
	}

	return nil
}

func getScanTaskByDigest(ctx context.Context, mongodb *mongotools.DatabaseWrapper, digest string) (model.ScanTask, bool, error) {
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

	singleResult := mongodb.Get().Collection(model.ScanTasksCollection.String()).FindOne(mongoCtx, filter, findOptions)
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

func GetPodNamesFromService(mongodb *mongo.Database, cluster, namespace, resName string) ([]string, error) {
	filter := bson.M{
		"$and": []bson.M{
			{"namespace": namespace},
			{"name": resName},
			{"cluster": cluster},
		},
	}
	// from mongo

	mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(5 * time.Second)

	cur, err := mongodb.Collection(model.PodServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find document: %w", err))
	}
	podsMap := make(map[string]struct{}, 10)
	for cur.Next(mongoCtx) {
		var service model.PodServiceRelation
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

func GetServiceSha256Val(mongodb *mongotools.DatabaseWrapper, namespace, snvName string) ([]string, error) {

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
	opt.SetMaxTime(2 * time.Second)

	cur, err := mongodb.Get().Collection(model.PodServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}
	podNameSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var rel model.PodServiceRelation
		err := cur.Decode(&rel)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		podNameSlice = append(podNameSlice, rel.PodName)
	}

	filter = bson.M{
		"isDeleted": false,
		"namespace": namespace,
		"podName":   bson.D{{"$in", podNameSlice}},
	}

	opts := options.Find()
	opts.SetMaxTime(time.Second * 2)

	coll := mongodb.Get().Collection(model.AssetsContainersCollection.String())

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

	cur, err := mongodb.Collection(model.PodServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}
	podNameSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var rel model.PodServiceRelation
		err := cur.Decode(&rel)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		podNameSlice = append(podNameSlice, rel.PodName)
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

func GetServiceImages(mongodb *mongotools.DatabaseWrapper, namespace, snvName string) ([]string, error) {

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
	opt.SetMaxTime(2 * time.Second)

	cur, err := mongodb.Get().Collection(model.PodServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}
	podNameSlice := make([]string, 0)
	for cur.Next(mongoCtx) {
		var service model.PodServiceRelation
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
	opts.SetMaxTime(time.Second * 2)

	coll := mongodb.Get().Collection(model.AssetsContainersCollection.String())

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

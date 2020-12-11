package scapper

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type Scapper struct {
	DockerRepoHostPort string
	DockerRepoScapTag  string
	MongoDB            *mongo.Database
	MongoEndpoint      string
	MongoUsername      string
	MongoPassword      string
	MongoDatabase      string
	MongoSecretName    string
	ScapService        *ScapService
}

const (
	// Potentially move to config file.

	checkTimeout           = time.Minute * 10
	historicalChecksToKeep = 3
)

func (s *Scapper) RunComplianceCheck(ctx, rootCtx context.Context, clusterObjectID primitive.ObjectID, cluster *model.Cluster, checkType model.ComplianceCheckType) (uuid.UUID, error) {
	// get namespace of this pod - it will be used for scheduled jobs/pods
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	someJobStillInProgress, err := s.removeOrphanedInProgressJobsAndSeeIfAnyRemain(ctx, checkType, namespace)
	if err != nil {
		return uuid.Nil, err
	}

	if someJobStillInProgress {
		return uuid.Nil, NewCheckAlreadyInProgressError(http.StatusConflict, fmt.Errorf("Check of this type is already running"))
	}

	kubeClient, err := k8s.KubeClientFromB64KubeConfig(cluster.KubeConfig)
	if err != nil {
		return uuid.Nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to create kube client: %w", err))
	}

	err = s.garbageCollectHistoricalJobs(ctx, kubeClient, checkType, namespace)
	if err != nil {
		return uuid.Nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to garbage collect historical jobs: %w", err))
	}

	// generate check uuid that will identify results of this run in database
	checkUUID := uuid.NewV4()

	check := scapper.Check{
		CheckType: checkType,
		CheckUUID: checkUUID,
		ClusterID: clusterObjectID.Hex(),
		Namespace: namespace,
	}

	jobObj, err := s.prepareJobObject(&check)
	if err != nil {
		return uuid.Nil, err
	}

	// find nodes to schedule check jobs on
	nodes, err := kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		return uuid.Nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Can't list nodes in this cluster: %w", err))
	}

	// schedule jobs
	logging.GetLogger().Info().
		Str("check-type", fmt.Sprintf("%s", check.CheckType)).
		Str("check-cluster", check.ClusterID).
		Str("check-uuid", check.CheckUUID.String()).
		Str("namespace", check.Namespace).
		Str("image", jobObj.Spec.Template.Spec.Containers[0].Image).
		Msg("Scheduling SCAP check jobs")

	for _, targetNode := range nodes.Items {
		// TODO: resilience. We should save a task to mongo so that in case of Console crash we can restart the check?
		// or do we not care about this since this is a rare operation?

		err := s.mongoAddJobStatusInProgress(ctx, &check, targetNode.Name)
		if err != nil {
			return uuid.Nil, err
		}
	}

	// async context is rooted in application context
	asyncCtx, _ := context.WithTimeout(rootCtx, checkTimeout)
	go s.asyncScheduleAndManageJobs(asyncCtx, kubeClient, &check, jobObj, nodes)

	s.ScapService.RefreshCache(check.CheckType)

	return checkUUID, nil
}

func (s *Scapper) removeOrphanedInProgressJobsAndSeeIfAnyRemain(ctx context.Context, checkType model.ComplianceCheckType, namespace string) (bool, error) {

	someJobStillInProgress := false

	// There may be orphaned jobs stuck in 'in-progress' state. We need to
	// find orhpaned in-progress jobs of this checkType and in this namespace
	// and remove them first.

	filter := bson.M{"status": model.ComplianceCheckStatusInProgress}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := s.MongoDB.Collection(model.GetMongoCollectionForCheckType(checkType)).Find(mongoCtx, filter)
	if err != nil {
		return true, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Orphan collection - can't list in-progress checks: %w", err))
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var result model.ComplianceCheckEntryBase
		err := cursor.Decode(&result)
		if err != nil {
			return true, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Orphan collection - couldn't decode entry: %w", err))
		}

		if result.Status == model.ComplianceCheckStatusInProgress {
			if time.Now().Unix()-result.CreatedAt > int64(checkTimeout.Seconds()) {
				// This job's status should've been updated to something else already.
				// Set it to failed.

				logging.GetLogger().Info().
					Str("checkId", result.CheckID).
					Str("nodeName", result.NodeName).
					Msg("Found orphaned inprogress job, will set its status to failed")

				checkUUID, err := uuid.FromString(result.CheckID)
				if err != nil {
					return true, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Orphan collection - check UUID malformed: %w", err))
				}

				check := scapper.Check{
					CheckType: checkType,
					CheckUUID: checkUUID,
					ClusterID: result.ClusterID,
					Namespace: namespace,
				}
				s.mongoJobStatusToFailed(ctx, &check, result.NodeName, "Timed out (found during GC)", time.Now().Unix())
			} else {
				someJobStillInProgress = true
			}
		}
	}

	err = cursor.Err()
	if err != nil {
		return true, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Orphan collection - cursor error: %w", err))
	}

	return someJobStillInProgress, nil
}

func (s *Scapper) garbageCollectHistoricalJobs(ctx context.Context, kubeClient *kubernetes.Clientset, checkType model.ComplianceCheckType, namespace string) error {
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"TENSORSEC": "true",
		},
	}
	listOpts := metav1.ListOptions{}
	listOpts.LabelSelector = labels.Set(labelSelector.MatchLabels).String()

	jobs, err := kubeClient.BatchV1().Jobs(namespace).List(listOpts)
	if err != nil {
		return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Can't list jobs in this cluster: %w", err))
	}

	// Find the start time of the earliest job in each check
	startTimesOfChecks := make(map[string]time.Time)
	for _, job := range jobs.Items {
		checkID, ok := job.Labels["CHECK_ID"]
		if !ok {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Expected CHECK_ID label to be present"))
		}

		if job.Status.StartTime == nil {
			logging.GetLogger().Info().Str("job-name", job.Name).Msg("StartTime is nil, skipping")
			continue
		}
		thisJobStartTime := job.Status.StartTime.Time

		earliestJobStartTimeSoFar, ok := startTimesOfChecks[checkID]
		if !ok {
			startTimesOfChecks[checkID] = thisJobStartTime
		} else {
			if earliestJobStartTimeSoFar.After(thisJobStartTime) {
				startTimesOfChecks[checkID] = thisJobStartTime
			}
		}
	}

	// We will be scheduling an additional check, so to keep historicalChecksToKeep, we must remove an additional one.
	// E.g. if there are 10 checks in history, and we have historicalChecksToKeep==3, we must remove 8,
	// so that there are 2 historical left. Because in a second, a new one will be scheduled (for a total of 3 historical).
	actualHistoricalChecksToKeep := historicalChecksToKeep - 1

	// check if there are enough historical checks to warrant further deletion steps.
	if len(startTimesOfChecks) <= actualHistoricalChecksToKeep {
		return nil
	}

	// Sort by start time
	type tempSortKeyValStruct struct {
		CheckID   string
		StartTime time.Time
	}
	var checksByStartTime []tempSortKeyValStruct
	for k, v := range startTimesOfChecks {
		checksByStartTime = append(checksByStartTime, tempSortKeyValStruct{k, v})
	}
	sort.Slice(checksByStartTime, func(i, j int) bool {
		return checksByStartTime[i].StartTime.Before(checksByStartTime[j].StartTime)
	})

	// Pop newest checks
	// note: we already checked boundary condition (array too short) before.
	checksByStartTime = checksByStartTime[:len(checksByStartTime)-actualHistoricalChecksToKeep]

	// Delete the job objects of remaining checks
	for _, job := range jobs.Items {
		// already validated that this label exists
		checkID, _ := job.Labels["CHECK_ID"]

		for _, toDelete := range checksByStartTime {
			if checkID == toDelete.CheckID {

				err := s.deleteJobAndPods(kubeClient, namespace, &job)
				if err != nil {
					return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to cleanup historical job: %w", err))
				}
				logging.GetLogger().Info().Str("job-name", job.Name).Msg("Cleaned up historical job")
				break
			}
		}
	}

	return nil
}

func (s *Scapper) asyncScheduleAndManageJobs(ctx context.Context, kubeClient *kubernetes.Clientset, check *scapper.Check, jobObj *batchv1.Job, nodes *corev1.NodeList) {

	scheduledNodesCh := make(chan string, len(nodes.Items))
	finishedNodesCh, listenerStopCh, cacheSynced := s.startAsyncStatusListener(ctx, kubeClient, check, len(nodes.Items))

	if !cacheSynced {
		logging.GetLogger().Warn().Msg("Informer cache failed to sync, not sure how to handle this. Ignoring.")
	}

	go s.awaitAndUpdateJobsStatuses(ctx, check, scheduledNodesCh, finishedNodesCh, listenerStopCh)

	for _, targetNode := range nodes.Items {
		select {
		case <-ctx.Done():
			logging.GetLogger().Error().Err(ctx.Err()).Msg("Ctx timeout while scheduling jobs")
			close(scheduledNodesCh)
			return
		default:
			// TODO: will it scale?
			// Note: I think it's safe to run this as goroutine for each job,
			// but I don't know if we should spam kube api this way...
			// I know kubeClient has some built in rate limiting so maybe it's ok?
			// Note2: but we must close scheduledNodesCh after all jobs were scheduled.
			// go func() {
			err := s.scheduleOneJob(kubeClient, check, jobObj.DeepCopy(), targetNode.Name)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to schedule job")
				s.mongoJobStatusToFailed(ctx, check, targetNode.Name, fmt.Sprintf("Failed to schedule job: %s", err), time.Now().Unix())
			} else {
				scheduledNodesCh <- targetNode.Name
			}
			// }()
		}
	}
	close(scheduledNodesCh)

}

func (s Scapper) GetMongoCollectionForCheckType(checkType model.ComplianceCheckType) string {
	if checkType == model.ComplianceCheckTargetTypeKube {
		return model.ComplianceCheckKubeRecordsCollection.String()
	} else if checkType == model.ComplianceCheckTargetTypeDocker {
		return model.ComplianceCheckDockerRecordsCollection.String()
	} else if checkType == model.ComplianceCheckTargetTypeHost {
		return model.ComplianceCheckHostRecordsCollection.String()
	} else {
		return ""
	}
}

func (s Scapper) prepareJobObject(check *scapper.Check) (*batchv1.Job, error) {
	jobObj, err := s.readJobObjFromYamlFile(check.CheckType)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Can't read job .yaml file")
		return nil, err
	}

	// Subsitute job's image repository in job.yaml for the one configured for Console.
	currImage := jobObj.Spec.Template.Spec.Containers[0].Image
	splitted := strings.Split(currImage, "/")
	currImgnameSplit := strings.Split(splitted[1], ":")
	currImgname := currImgnameSplit[0]
	newImage := fmt.Sprintf("%s/%s:%s", s.DockerRepoHostPort, currImgname, s.DockerRepoScapTag)
	jobObj.Spec.Template.Spec.Containers[0].Image = newImage

	return jobObj, nil
}

func (s Scapper) readJobObjFromYamlFile(checkType model.ComplianceCheckType) (*batchv1.Job, error) {
	jobYamlPath := ""
	if checkType == model.ComplianceCheckTargetTypeKube {
		jobYamlPath = "/jobs/kube-bench/job.yaml"
	} else if checkType == model.ComplianceCheckTargetTypeDocker {
		jobYamlPath = "/jobs/docker-bench-security/job.yaml"
	} else if checkType == model.ComplianceCheckTargetTypeHost {
		jobYamlPath = "/jobs/host-bench/job.yaml"
	} else {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Unreachable code reached"))
	}

	jobYaml, err := ioutil.ReadFile(jobYamlPath)
	if err != nil {
		return nil, NewConfigurationError(http.StatusInternalServerError, fmt.Errorf("Can't read job file: %w", err))
	}

	jobObj := &batchv1.Job{}
	decoder := k8Yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(jobYaml)), 1000)
	err = decoder.Decode(&jobObj)
	if err != nil {
		return nil, NewConfigurationError(http.StatusInternalServerError, fmt.Errorf("Can't decode job file: %w", err))

	}
	return jobObj, nil
}

func (s *Scapper) scheduleOneJob(kubeClient *kubernetes.Clientset, check *scapper.Check, jobObj *batchv1.Job, targetNodeName string) error {
	jobObj.Spec.Template.Spec.NodeName = targetNodeName

	if jobObj.Labels == nil {
		jobObj.Labels = make(map[string]string)
	}
	jobObj.Labels["CHECK_ID"] = check.CheckUUID.String()
	jobObj.Labels["TENSORSEC"] = "true"

	jobObj.Name = fmt.Sprintf("%s-%s", check.CheckUUID.String()[:8], jobObj.Name)

	checkEnv := corev1.EnvVar{
		Name:  "CHECK_ID",
		Value: check.CheckUUID.String(),
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, checkEnv)

	nodeNameEnv := corev1.EnvVar{
		Name:  "NODE_NAME",
		Value: targetNodeName,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, nodeNameEnv)

	mongoString := fmt.Sprintf("mongodb://%s:$TENSORSEC_MONGO_PASSWORD@%s/%s?authSource=%s",
		s.MongoUsername, s.MongoEndpoint, s.MongoDatabase, s.MongoDatabase)
	mongoStringEnv := corev1.EnvVar{
		Name:  "MONGO_STRING",
		Value: mongoString,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, mongoStringEnv)

	mongoSecretEnv := corev1.EnvVar{
		Name: "TENSORSEC_MONGO_PASSWORD",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: s.MongoSecretName,
				},
				Key: "mongodb-password",
			},
		},
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, mongoSecretEnv)

	jobObj.Name = fmt.Sprintf("%s-%s", jobObj.Name, targetNodeName)

	jobsClient := kubeClient.BatchV1().Jobs(check.Namespace)
	res, err := jobsClient.Create(jobObj)
	// HACK
	if k8serrors.IsAlreadyExists(err) {
		err = jobsClient.Delete(jobObj.Name, &metav1.DeleteOptions{})
		if err != nil {
			return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Job already exists, so tried deleting, but: %w", err))
		}

		time.Sleep(time.Second * 10)
		res, err = jobsClient.Create(jobObj)
	}
	if err != nil {
		return NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Couldn't schedule job: %w", err))
	}

	jobName := res.ObjectMeta.Name

	logging.GetLogger().Info().
		Str("target-node", jobObj.Spec.Template.Spec.NodeName).
		Str("job-name", jobName).
		Msg("Scheduled SCAP check job")

	return nil
}

func (s *Scapper) mongoAddJobStatusInProgress(ctx context.Context, check *scapper.Check, targetNodeName string) error {
	now := time.Now()
	secs := now.Unix()
	entry := model.JobEntry{
		ID:        primitive.NewObjectIDFromTimestamp(now),
		CheckID:   check.CheckUUID.String(),
		NodeName:  targetNodeName,
		ClusterID: check.ClusterID,
		Status:    model.ComplianceCheckStatusInProgress,
		CreatedAt: secs,
	}
	err := s.MongoDB.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		_, sessionError = s.MongoDB.Collection(model.GetMongoCollectionForCheckType(check.CheckType)).InsertOne(ctx, entry)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed insert to mongo: %w", sessionError))
		}
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update scap job document: %w", sessionError))
		}
		sessionError = s.updateScapReports(sessionContext, check, targetNodeName)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to update scap reports: %w", sessionError))
			logging.GetLogger().Error().
				Str("checkId", check.CheckUUID.String()).
				Str("nodeName", targetNodeName).
				Msg("Failed to update scap reports")
		}
		return nil
	})
	if err != nil {
		logging.GetLogger().Error().
			Err(err).
			Str("checkId", check.CheckUUID.String()).
			Str("nodeName", targetNodeName).
			Msg("Failed to commit scap update transaction")
	}
	return err
}

func (s *Scapper) mongoJobStatusToFailed(ctx context.Context, check *scapper.Check, nodeName, msg string, timeEpochSecs int64) {
	filter := bson.M{"checkId": check.CheckUUID.String(), "nodeName": nodeName}
	// TODO: is there better way to do this using struct annotations?
	update := bson.M{"$set": bson.M{
		"status":          model.ComplianceCheckStatusFailed,
		"finishedAt":      timeEpochSecs,
		"message":         msg,
		"audit_timestamp": time.Now(),
	}}
	err := s.MongoDB.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		_, sessionError = s.MongoDB.Collection(model.GetMongoCollectionForCheckType(check.CheckType)).UpdateOne(ctx, filter, update)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update scap job document: %w", sessionError))
		}
		sessionError = s.updateScapReports(sessionContext, check, nodeName)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to update scap reports: %w", sessionError))
			logging.GetLogger().Error().
				Str("checkId", check.CheckUUID.String()).
				Str("nodeName", nodeName).
				Msg("Failed to update scap reports")
		}
		return nil
	})
	if err != nil {
		logging.GetLogger().Error().
			Err(err).
			Str("checkId", check.CheckUUID.String()).
			Str("nodeName", nodeName).
			Msg("Failed to commit scap update transaction")
	}
}

func (s *Scapper) updateScapReports(ctx context.Context, check *scapper.Check, nodeName string) error {
	filter := bson.M{"checkId": check.CheckUUID.String()}
	findOptions := options.Find().SetMaxTime(time.Second * 10)
	cursor, err := s.MongoDB.Collection(model.GetMongoCollectionForCheckType(check.CheckType)).Find(ctx, filter, findOptions)
	if err != nil {
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to find documents: %w", err))
	}
	defer cursor.Close(ctx)

	checkFindOneOptions := options.FindOne().SetMaxTime(time.Second * 10)
	var oldCheckHistory model.CheckHistoryEntry
	res := s.MongoDB.Collection(model.CheckHistoryEntryCollection.String()).FindOne(ctx, filter, checkFindOneOptions)
	var checkHistory model.CheckHistoryEntry
	if res.Err() != nil {
		if res.Err() == mongo.ErrNoDocuments {
			checkHistory = model.CheckHistoryEntry{
				ID:        primitive.NewObjectIDFromTimestamp(time.Now()),
				CheckID:   check.CheckUUID.String(),
				ClusterID: check.ClusterID,
				CreatedAt: math.MaxInt64,
				CheckType: string(check.CheckType),
			}
		} else {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", res.Err()))
		}
	} else {
		err = res.Decode(&oldCheckHistory)
		if err != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		checkHistory = model.CheckHistoryEntry{
			ID:        oldCheckHistory.ID,
			CheckID:   check.CheckUUID.String(),
			ClusterID: check.ClusterID,
			CreatedAt: math.MaxInt64,
			CheckType: string(check.CheckType),
		}
	}

	for cursor.Next(ctx) {
		var result model.ComplianceCheckEntryBase
		err = cursor.Decode(&result)
		switch check.CheckType {
		case model.ComplianceCheckTargetTypeKube:
			var complianceTest model.KubeJobEntry
			err := cursor.Decode(&complianceTest)
			if err != nil {
				return err
			}
			if complianceTest.CreatedAt < checkHistory.CreatedAt {
				checkHistory.CreatedAt = complianceTest.CreatedAt
			}
			if checkHistory.FinishedAt != -1 {
				if complianceTest.Status == model.ComplianceCheckStatusInProgress {
					// Set to -1 not to 0, because 0 is the starting value.
					checkHistory.FinishedAt = -1
				} else {
					if checkHistory.FinishedAt < complianceTest.FinishedAt {
						checkHistory.FinishedAt = complianceTest.FinishedAt
					}
				}
			}
			if complianceTest.Status == model.ComplianceCheckStatusInProgress {
				checkHistory.NumWaiting++
				continue
			}
			if complianceTest.Status == model.ComplianceCheckStatusFailed {
				checkHistory.NumError++
				continue
			}
			policiesFailed := int64(0)
			policiesInconclusive := int64(0)
			policiesPassed := int64(0)
			for _, reportDetails := range complianceTest.Report {
				for _, section := range reportDetails.Tests {
					policiesFailed += section.Fail
					policiesPassed += section.Pass
					policiesInconclusive += section.Info
					policiesInconclusive += section.Warn
				}
			}

			checkHistory.TotalPoliciesPassed += policiesPassed
			checkHistory.TotalPoliciesTried += policiesFailed + policiesInconclusive + policiesPassed

			if policiesFailed != 0 {
				checkHistory.NumFailed++
			} else if policiesInconclusive != 0 {
				checkHistory.NumInconclusive++
			} else {
				checkHistory.NumSuccessful++
			}

		case model.ComplianceCheckTargetTypeDocker:
			var complianceTest model.DockerJobEntry
			err := cursor.Decode(&complianceTest)
			if err != nil {
				return err
			}
			if complianceTest.CreatedAt < checkHistory.CreatedAt {
				checkHistory.CreatedAt = complianceTest.CreatedAt
			}
			if checkHistory.FinishedAt != -1 {
				if complianceTest.Status == model.ComplianceCheckStatusInProgress {
					// Set to -1 not to 0, because 0 is the starting value.
					checkHistory.FinishedAt = -1
				} else {
					if checkHistory.FinishedAt < complianceTest.FinishedAt {
						checkHistory.FinishedAt = complianceTest.FinishedAt
					}
				}
			}
			if complianceTest.Status == model.ComplianceCheckStatusInProgress {
				checkHistory.NumWaiting++
				continue
			}
			if complianceTest.Status == model.ComplianceCheckStatusFailed {
				checkHistory.NumError++
				continue
			}
			policiesFailed := int64(0)
			policiesInconclusive := int64(0)
			policiesPassed := int64(0)
			for _, test := range complianceTest.Report.Tests {
				for _, result := range test.Results {
					if result.Result == "INFO" {
						policiesInconclusive++
					} else if result.Result == "NOTE" {
						policiesInconclusive++
					} else if result.Result == "PASS" {
						policiesPassed++
					} else {
						policiesFailed++
					}
				}
			}

			checkHistory.TotalPoliciesPassed += policiesPassed
			checkHistory.TotalPoliciesTried += policiesFailed + policiesInconclusive + policiesPassed

			if policiesFailed != 0 {
				checkHistory.NumFailed++
			} else if policiesInconclusive != 0 {
				checkHistory.NumInconclusive++
			} else {
				checkHistory.NumSuccessful++
			}

		case model.ComplianceCheckTargetTypeHost:
			var complianceTest model.HostJobEntry
			err := cursor.Decode(&complianceTest)
			if err != nil {
				return err
			}
			if complianceTest.CreatedAt < checkHistory.CreatedAt {
				checkHistory.CreatedAt = complianceTest.CreatedAt
			}
			if checkHistory.FinishedAt != -1 {
				if complianceTest.Status == model.ComplianceCheckStatusInProgress {
					// Set to -1 not to 0, because 0 is the starting value.
					checkHistory.FinishedAt = -1
				} else {
					if checkHistory.FinishedAt < complianceTest.FinishedAt {
						checkHistory.FinishedAt = complianceTest.FinishedAt
					}
				}
			}
			if complianceTest.Status == model.ComplianceCheckStatusInProgress {
				checkHistory.NumWaiting++
				continue
			}
			if complianceTest.Status == model.ComplianceCheckStatusFailed {
				checkHistory.NumError++
				continue
			}
			policiesFailed := int64(0)
			policiesInconclusive := int64(0)
			policiesPassed := int64(0)
			for _, test := range complianceTest.Report.Results {
				if test.Result == "notselected" {
					policiesInconclusive++
				} else if test.Result == "pass" {
					policiesPassed++
				} else if test.Result == "fail" {
					policiesFailed++
				}
			}

			checkHistory.TotalPoliciesPassed += policiesPassed
			checkHistory.TotalPoliciesTried += policiesFailed + policiesInconclusive + policiesPassed

			if policiesFailed != 0 {
				checkHistory.NumFailed++
			} else if policiesInconclusive != 0 {
				checkHistory.NumInconclusive++
			} else {
				checkHistory.NumSuccessful++
			}
		default:
			return NewAnError(http.StatusInternalServerError, fmt.Errorf("Unexpected checkType %s", check.CheckType))
		}
	}
	finishedNodesNum := checkHistory.NumFailed + checkHistory.NumInconclusive + checkHistory.NumSuccessful
	if finishedNodesNum != 0 {
		checkHistory.Score = float32(checkHistory.TotalPoliciesPassed) / float32(finishedNodesNum)
		checkHistory.MaxScore = float32(checkHistory.TotalPoliciesTried) / float32(finishedNodesNum)
	}
	if checkHistory.NumWaiting == 0 {
		checkHistory.HistoricisedTimestamp = time.Now()
	}
	filter = bson.M{"checkId": check.CheckUUID.String()}
	update := bson.M{"$set": checkHistory}
	opts := options.Update().SetUpsert(true)

	_, err = s.MongoDB.Collection(model.CheckHistoryEntryCollection.String()).UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", err))
	}

	return nil
}

func (s *Scapper) startAsyncStatusListener(ctx context.Context, kubeClient *kubernetes.Clientset, check *scapper.Check, maxNumJobs int) (chan string, chan struct{}, bool) {
	finishedNodesCh := make(chan string, maxNumJobs)

	kubeInformerFactory := informers.NewFilteredSharedInformerFactory(kubeClient, time.Second*30, check.Namespace, func(listOpts *v1.ListOptions) {
		labelSelector := metav1.LabelSelector{
			MatchLabels: map[string]string{
				"CHECK_ID": check.CheckUUID.String(),
			},
		}
		listOpts.LabelSelector = labels.Set(labelSelector.MatchLabels).String()
	})
	jobInformer := kubeInformerFactory.Batch().V1().Jobs().Informer()

	// Keep track of already finished nodes, so that we don't handle events for further updates after they're done.
	alreadyFinishedNodes := make(map[string]bool)

	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {},
		DeleteFunc: func(obj interface{}) {
			job, ok := obj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().
					Str("obj-type", fmt.Sprintf("%T", obj)).
					Msg("Failed to cast to *batchv1.Job")
				return
			}
			thisNodeName := job.Spec.Template.Spec.NodeName
			if _, ok := alreadyFinishedNodes[thisNodeName]; ok {
				return
			}

			err := s.containerLogsToMongo(ctx, kubeClient, job.Namespace, job.Name, thisNodeName, check)
			if err != nil {
				logging.GetLogger().Error().Err(err).
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Failed to get logs, ignoring")
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			job, ok := newObj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().
					Str("obj-type", fmt.Sprintf("%T", newObj)).
					Msg("Failed to cast to *batchv1.Job")
				return
			}

			thisNodeName := job.Spec.Template.Spec.NodeName
			if _, ok := alreadyFinishedNodes[thisNodeName]; ok {
				return
			}

			err := s.containerLogsToMongo(ctx, kubeClient, job.Namespace, job.Name, thisNodeName, check)
			if err != nil {
				logging.GetLogger().Error().Err(err).
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Failed to get logs, ignoring")
			}

			// Finished successfuly?
			if job.Status.Succeeded > 0 {
				logging.GetLogger().Info().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Managed job succeeded")

				finishedNodesCh <- thisNodeName
				alreadyFinishedNodes[thisNodeName] = true

				return
			}

			// Finished and failed?
			if isFailed, failedCondition := s.isJobFailed(job); isFailed {
				logging.GetLogger().Info().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Managed job failed")

				thisNodeName := job.Spec.Template.Spec.NodeName
				finishedNodesCh <- thisNodeName
				alreadyFinishedNodes[thisNodeName] = true

				transTime := failedCondition.LastTransitionTime
				msg := fmt.Sprintf("Message: %s; Reason: %s", failedCondition.Message, failedCondition.Reason)

				mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
				defer mongoCtxCancel()
				s.mongoJobStatusToFailed(mongoCtx, check, thisNodeName, msg, transTime.Unix())

				return
			}

			// some other event happened - pass.
			return
		},
	})

	stopCh := make(chan struct{})

	logging.GetLogger().Info().
		Str("checkId", check.CheckUUID.String()).
		Msg("Starting to watch for job events")
	kubeInformerFactory.Start(stopCh)

	var jobType *batchv1.Job
	cacheSynced := kubeInformerFactory.WaitForCacheSync(stopCh)[reflect.TypeOf(jobType)]

	return finishedNodesCh, stopCh, cacheSynced
}

func (s *Scapper) containerLogsToMongo(ctx context.Context, kubeClient *kubernetes.Clientset, jobNamespace, jobName, nodeName string, check *scapper.Check) error {
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"job-name": jobName,
		},
	}
	listOpts := metav1.ListOptions{LabelSelector: labels.Set(labelSelector.MatchLabels).String()}

	podList, err := kubeClient.CoreV1().Pods(jobNamespace).List(listOpts)
	if err != nil {
		return fmt.Errorf("Failed to list pods of jobs: %w", err)
	}

	if len(podList.Items) != 1 {
		return fmt.Errorf("Expected exactly 1 pod per 1 job, got %d", len(podList.Items))
	}

	pod := podList.Items[0]

	if len(pod.Spec.Containers) != 1 {
		return fmt.Errorf("Expected exactly 1 container in 1 pod, got %d, "+
			"please either adjust deployment.yaml or PodLogOptions", len(pod.Spec.Containers))
	}

	podLogOpts := corev1.PodLogOptions{
		// If more containers added to this pod, specify
		//Container: ...
	}

	req := kubeClient.CoreV1().Pods(jobNamespace).GetLogs(pod.Name, &podLogOpts)
	podLogs, err := req.Stream()
	if err != nil {
		return fmt.Errorf("Error in opening pod log stream: %w", err)
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return fmt.Errorf("Error copying pod logs to buffer: %w", err)
	}

	encodedLogs := base64.StdEncoding.EncodeToString(buf.Bytes())

	filter := bson.M{"checkId": check.CheckUUID.String(), "nodeName": nodeName}
	update := bson.M{"$set": bson.M{
		"logs": encodedLogs,
	}}
	opts := options.Update().SetUpsert(true)

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	_, err = s.MongoDB.Collection(model.GetMongoCollectionForCheckType(check.CheckType)).UpdateOne(mongoCtx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("Failed to upsert container logs: %w", err)
	}
	return nil
}

func (s *Scapper) awaitAndUpdateJobsStatuses(ctx context.Context, check *scapper.Check, scheduledNodesCh, finishedNodesCh chan string, listenerStopCh chan struct{}) {
	defer close(listenerStopCh)

	// I think this design is kinda fragile... but I don't have any quick ideas.
	// A better design would be to create a k8s custom resource with a custom controller to manage it.

	runningNodeNames := []string{}

	for {
		select {
		case <-ctx.Done():
			logging.GetLogger().Error().Err(ctx.Err()).Msg("Ctx timeout while waiting for jobs to finish, will mark them as timed out")
			// mark remaining running jobs as timed out.
			now := time.Now().Unix()
			for _, runningNodeName := range runningNodeNames {
				// use context.Background instead of local ctx, because local ctx is already timed out so mongo operation would fail.
				mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
				s.mongoJobStatusToFailed(mongoCtx, check, runningNodeName, fmt.Sprintf("Timed out: %s", ctx.Err()), now)
				mongoCtxCancel()
			}
			return

		case scheduledNodeName, ok := <-scheduledNodesCh:
			if !ok {
				scheduledNodesCh = nil
				continue
			}
			runningNodeNames = append(runningNodeNames, scheduledNodeName)
			logging.GetLogger().Info().Str("node-name", scheduledNodeName).Int("num-running-jobs-left", len(runningNodeNames)).Msg("Job scheduled")

		case finishedNodeName, ok := <-finishedNodesCh:
			if !ok {
				finishedNodesCh = nil
				continue
			}
			runningNodeNames = removeElement(finishedNodeName, runningNodeNames)
			logging.GetLogger().Info().Str("node-name", finishedNodeName).Int("num-running-jobs-left", len(runningNodeNames)).Msg("Job finished")

			mongoCtx, mongoCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
			defer mongoCtxCancel()
			s.updateScapReports(mongoCtx, check, finishedNodeName)

			if len(runningNodeNames) == 0 {
				logging.GetLogger().Info().
					Str("checkId", check.CheckUUID.String()).
					Msg("All managed jobs accounted for, done watching for events")

				err := s.generateAlerts(ctx, check)
				if err != nil {
					logging.GetLogger().Error().
						Str("checkId", check.CheckUUID.String()).
						Msg("Failed to generate alerts")
				}

				return
			}
		}

		if scheduledNodesCh == nil && finishedNodesCh == nil {
			logging.GetLogger().Error().
				Msg("Both chans are nil, this shouldn't happen")
		}
	}

}

func (s Scapper) GetJobEntriesForCheck(ctx context.Context, clusterID string, checkType model.ComplianceCheckType, checkID, nodeName, status string) ([]model.JobEntry, error) {

	filter := bson.M{"clusterId": clusterID}

	if checkID != "" {
		filter["checkId"] = checkID
	}

	if nodeName != "" {
		filter["nodeName"] = nodeName
	}

	if status != "" {
		if status != model.ComplianceCheckStatusCompleted && status != model.ComplianceCheckStatusInProgress && status != model.ComplianceCheckStatusFailed {
			allowed := strings.Join([]string{model.ComplianceCheckStatusCompleted, model.ComplianceCheckStatusInProgress, model.ComplianceCheckStatusFailed}, "/")
			return []model.JobEntry{}, NewFieldError(http.StatusBadRequest,
				fmt.Errorf("invalid status param value (allowed: %s)", allowed),
				Suberror{"status", fmt.Sprintf("allowed: %s", allowed)})
		}
		filter["status"] = status
	}

	cursor, err := s.MongoDB.Collection(model.GetMongoCollectionForCheckType(checkType)).Find(ctx, filter)
	if err != nil {
		return []model.JobEntry{}, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find documents: %w", err))
	}
	defer cursor.Close(ctx)

	var results []model.JobEntry
	for cursor.Next(ctx) {
		var result model.JobEntry
		err := cursor.Decode(&result)
		if err != nil {
			return []model.JobEntry{}, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Couldn't decode document: %w", err))
		}
		// TODO: pagination, maybe https://github.com/gobeam/mongo-go-pagination?
		results = append(results, result)
	}

	err = cursor.Err()
	if err != nil {
		return []model.JobEntry{}, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Cursor error: %w", err))
	}

	return results, nil
}

func (s Scapper) isJobFailed(job *batchv1.Job) (bool, *batchv1.JobCondition) {
	var failedCondition *batchv1.JobCondition
	failedCondition = nil
	for idx, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobFailed {
			// according to documentation of JobStatus,
			// "When a job fails, one of the conditions will have type == "Failed"."
			failedCondition = &job.Status.Conditions[idx]
		}
	}
	if failedCondition != nil {
		return true, failedCondition
	} else {
		return false, nil
	}
}

func (s *Scapper) deleteJobAndPods(kubeClient *kubernetes.Clientset, namespace string, job *batchv1.Job) error {
	err := kubeClient.BatchV1().Jobs(namespace).Delete(job.Name, &metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("Failed to delete job: %w", err)
	}

	listOpts := metav1.ListOptions{
		LabelSelector: labels.Set(job.Spec.Selector.MatchLabels).String(),
	}
	err = kubeClient.CoreV1().Pods(namespace).DeleteCollection(&metav1.DeleteOptions{}, listOpts)
	if err != nil {
		return fmt.Errorf("Failed to delete job's pods: %w", err)
	}
	return nil
}

func removeAtIdx(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

func removeElement(what string, from []string) []string {
	for idx, el := range from {
		if el == what {
			return removeAtIdx(from, idx)
		}
	}
	return from
}

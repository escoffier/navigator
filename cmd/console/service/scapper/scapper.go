package scapper

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scap"
	"gitlab.com/piccolo_su/vegeta/cmd/console/model/scapper"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
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
	MongoDB            *mongo.Database
	MongoEndpoint      string
	MongoUsername      string
	MongoPassword      string
	MongoDatabase      string
}

const (
	// Potentially move to config file.

	checkTimeout           = time.Minute * 10
	historicalChecksToKeep = 3
)

func (s *Scapper) RunComplianceCheck(ctx, rootCtx context.Context, clusterObjectID primitive.ObjectID, cluster *model.Cluster, checkType string) (uuid.UUID, error) {
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
		Str("check-type", check.CheckType).
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

	return checkUUID, nil
}

func (s *Scapper) removeOrphanedInProgressJobsAndSeeIfAnyRemain(ctx context.Context, checkType, namespace string) (bool, error) {

	someJobStillInProgress := false

	// There may be orphaned jobs stuck in 'in-progress' state. We need to
	// find orhpaned in-progress jobs of this checkType and in this namespace
	// and remove them first.

	filter := bson.M{"status": model.ComplianceCheckStatusInProgress}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := s.MongoDB.Collection(s.GetMongoCollectionForCheckType(checkType)).Find(mongoCtx, filter)
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

func (s *Scapper) garbageCollectHistoricalJobs(ctx context.Context, kubeClient *kubernetes.Clientset, checkType, namespace string) error {
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
	finishedNodesCh, listenerStopCh := s.startAsyncStatusListener(ctx, kubeClient, check, len(nodes.Items))

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

func (s Scapper) GetMongoCollectionForCheckType(checkType string) string {
	if checkType == "kube" {
		return "kube-bench-records"
	} else if checkType == "docker" {
		return "docker-bench-records"
	} else if checkType == "host" {
		return "host-bench-records"
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
	currImgname := splitted[1]
	newImage := fmt.Sprintf("%s/%s", s.DockerRepoHostPort, currImgname)
	jobObj.Spec.Template.Spec.Containers[0].Image = newImage

	return jobObj, nil
}

func (s Scapper) readJobObjFromYamlFile(checkType string) (*batchv1.Job, error) {
	jobYamlPath := ""
	if checkType == "kube" {
		jobYamlPath = "/jobs/kube-bench/job.yaml"
	} else if checkType == "docker" {
		jobYamlPath = "/jobs/docker-bench-security/job.yaml"
	} else if checkType == "host" {
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

	// TODO: This should be a secret. There's probably a better way to do this anyways.
	mongoString := fmt.Sprintf("mongodb://%s:%s@%s/%s?authSource=%s",
		s.MongoUsername, s.MongoPassword, s.MongoEndpoint, s.MongoDatabase, s.MongoDatabase)
	mongoStringEnv := corev1.EnvVar{
		Name:  "MONGO_STRING",
		Value: mongoString,
	}
	jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, mongoStringEnv)

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
	entry := scap.JobEntry{
		ID:        primitive.NewObjectIDFromTimestamp(now),
		CheckID:   check.CheckUUID.String(),
		NodeName:  targetNodeName,
		ClusterID: check.ClusterID,
		Status:    model.ComplianceCheckStatusInProgress,
		CreatedAt: secs,
	}

	_, err := s.MongoDB.Collection(s.GetMongoCollectionForCheckType(check.CheckType)).InsertOne(ctx, entry)
	if err != nil {
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed insert to mongo: %w", err))
	}

	return nil
}

func (s *Scapper) mongoJobStatusToFailed(ctx context.Context, check *scapper.Check, nodeName, msg string, timeEpochSecs int64) {
	filter := bson.M{"checkId": check.CheckUUID.String(), "nodeName": nodeName}
	// TODO: is there better way to do this using struct annotations?
	update := bson.M{"$set": bson.M{
		"status":     model.ComplianceCheckStatusFailed,
		"finishedAt": timeEpochSecs,
		"message":    msg,
	}}
	_, err := s.MongoDB.Collection(s.GetMongoCollectionForCheckType(check.CheckType)).UpdateOne(ctx, filter, update)
	if err != nil {
		logging.GetLogger().Error().
			Str("checkId", check.CheckUUID.String()).
			Str("nodeName", nodeName).
			Msg("Failed to update mongo entry status to failed")
	}
}

func (s *Scapper) startAsyncStatusListener(ctx context.Context, kubeClient *kubernetes.Clientset, check *scapper.Check, maxNumJobs int) (chan string, chan struct{}) {
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

	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) {},
		DeleteFunc: func(obj interface{}) {},
		UpdateFunc: func(oldObj, newObj interface{}) {
			job, ok := newObj.(*batchv1.Job)
			if !ok {
				logging.GetLogger().Error().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Failed to cast to *batchv1.Job")
				return
			}

			// Finished successfuly?
			if job.Status.Succeeded > 0 {
				logging.GetLogger().Info().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Managed job succeeded")

				thisNodeName := job.Spec.Template.Spec.NodeName
				finishedNodesCh <- thisNodeName
				return
			}

			// Finished and failed?
			if isFailed, failedCondition := s.isJobFailed(job); isFailed {
				logging.GetLogger().Info().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Managed job failed")

				thisNodeName := job.Spec.Template.Spec.NodeName
				finishedNodesCh <- thisNodeName

				transTime := failedCondition.LastTransitionTime
				msg := fmt.Sprintf("Message: %s; Reason: %s", failedCondition.Message, failedCondition.Reason)

				mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
				s.mongoJobStatusToFailed(mongoCtx, check, thisNodeName, msg, transTime.Unix())
				mongoCtxCancel()
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

	return finishedNodesCh, stopCh
}

func (s *Scapper) awaitAndUpdateJobsStatuses(ctx context.Context, check *scapper.Check, scheduledNodesCh, finishedNodesCh chan string, listenerStopCh chan struct{}) {
	defer close(listenerStopCh)

	// TODO: if console restarts while job is running, that job's events won't be watched.
	// TODO: rethink. Maybe we should have a listener thread all the time and utilize AddFunc
	// to listen to newly created jobs and keep track that way?
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

			if len(runningNodeNames) == 0 {
				logging.GetLogger().Info().
					Str("checkId", check.CheckUUID.String()).
					Msg("All managed jobs accounted for, done watching for events")
				return
			}
		}

		if scheduledNodesCh == nil && finishedNodesCh == nil {
			logging.GetLogger().Error().
				Msg("Both chans are nil, this shouldln't happen")
		}
	}

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

package api

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/{checkType}/{clusterID}/reportsummaries", api.getScapReports())
		r.Get("/{checkType}/{clusterID}/reports", api.getScapReports())
		r.Post("/{checkType}/{clusterID}", api.scapCheck())
	}
}

type JobEntry struct {
	ID         primitive.ObjectID     `json:"db_id,omitempty" bson:"_id,omitempty"`
	CheckID    string                 `json:"check_id" bson:"checkId"`
	NodeName   string                 `json:"node_name" bson:"nodeName"`
	ClusterID  string                 `json:"cluster_id" bson:"clusterId"`
	Status     string                 `json:"status" bson:"status,omitempty"`
	CreatedAt  int64                  `json:"created_at" bson:"createdAt,omitempty"`
	FinishedAt int64                  `json:"finished_at" bson:"finishedAt,omitempty"`
	Report     map[string]interface{} `json:"report" bson:"report,omitempty"`
}

type Check struct {
	CheckType string
	CheckUUID uuid.UUID
	ClusterID string
	Namespace string
}

// @Summary Get scap reports
// @Description Get scap report for cluster and filter criteria
// @ID v1-scap-job-get
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Param checkID query string false "check ID"
// @Param nodeName query string false "node name"
// @Param status query string false "status (inprogress/failed/completed)"
// @Router /api/v1/scap/{checkType}/{clusterID}/reports [get]
func (api *api) getScapReports() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return

		}
		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		filter := bson.M{"clusterId": clusterObjectID.Hex()}

		checkID := r.URL.Query().Get("checkId")
		if checkID != "" {
			filter["checkId"] = checkID
		}

		nodeName := r.URL.Query().Get("nodeName")
		if nodeName != "" {
			filter["nodeName"] = nodeName
		}

		status := r.URL.Query().Get("status")
		if status != "" {
			if status != "inprogress" && status != "failed" && status != "completed" {
				logging.GetLogger().Info().Msg("invalid status param value (allowed: inprogress/failed/completed)")
				response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("status", ""))
				return
			}
			filter["status"] = status
		}

		cursor, err := api.mongodb.Collection(api.getMongoCollectionForCheckType(checkType)).Find(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't find documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cursor.Close(ctx)

		var results []JobEntry
		for cursor.Next(ctx) {
			var result JobEntry
			err := cursor.Decode(&result)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			// TODO: pagination, maybe https://github.com/gobeam/mongo-go-pagination?
			results = append(results, result)
		}

		err = cursor.Err()
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Cursor error")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}

		response.Ok(w, response.WithItems(results))
	}
}

// @Summary Run compliance check on specified cluster
// @Description Run compliance check on specified cluster
// @ID v1-scap-check
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Router /api/v1/scap/{checkType}/{clusterID} [post]
func (api *api) scapCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			logging.GetLogger().Info().Msg("checkType param missing")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			logging.GetLogger().Info().Msg("invalid checkType param value (allowed: kube/docker/host)")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("checkType", ""))
			return
		}

		// get kube client for this cluster
		cluster, err := api.getClusterFromMongo(ctx, clusterObjectID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to get cluster from Mongo")
			apperror.RespondWithSuggested(w, r, err)
			return
		}

		kubeClient, err := kubeClientFromB64KubeConfig(cluster.KubeConfig)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Failed to create kube client")
			response.InternalError(w, response.WithMessage(locale.Error(locale.KubernetesError, r)))
			return
		}

		// generate check uuid that will identify results of this run in database
		checkUUID := uuid.NewV4()

		// get namespace of this pod - it will be used for scheduled jobs/pods
		namespace := os.Getenv("MY_POD_NAMESPACE")
		if namespace == "" {
			namespace = "default"
		}

		check := Check{
			CheckType: checkType,
			CheckUUID: checkUUID,
			ClusterID: clusterObjectID.Hex(),
			Namespace: namespace,
		}

		jobObj, err := api.prepareJobObject(&check)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to prepare job object")
			apperror.RespondWithSuggested(w, r, err)
			return
		}

		// find nodes to schedule check jobs on
		nodes, err := kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Can't list nodes in this cluster")
			response.InternalError(w, response.WithMessage(locale.Error(locale.KubernetesError, r)))
			return
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

			err := api.mongoAddJobStatusInProgress(ctx, &check, targetNode.Name)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to add job to mongo")
				apperror.RespondWithSuggested(w, r, err)
				return
			}
		}

		asyncCtx, _ := api.getTimeoutCtx(time.Minute * 10)
		go api.asyncScheduleAndManageJobs(asyncCtx, kubeClient, &check, jobObj, nodes)

		type resp struct {
			CheckUUID string `json:"checkUUID"`
		}

		response.Ok(w, response.WithItem(resp{
			CheckUUID: checkUUID.String(),
		}))
	}
}

func (api *api) asyncScheduleAndManageJobs(ctx context.Context, kubeClient *kubernetes.Clientset, check *Check, jobObj *batchv1.Job, nodes *corev1.NodeList) {

	scheduledNodesCh := make(chan string, len(nodes.Items))
	go api.asyncJobStatusUpdater(ctx, kubeClient, check, scheduledNodesCh, len(nodes.Items))

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
			// go func() {
			err := api.scheduleOneJob(kubeClient, check, jobObj.DeepCopy(), targetNode.Name)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to schedule job")
				api.mongoJobStatusToFailed(ctx, check, targetNode.Name, fmt.Sprintf("Failed to schedule job: %s", err), time.Now().Unix())
			} else {
				scheduledNodesCh <- targetNode.Name
			}
			// }()
		}
	}
	close(scheduledNodesCh)

}

func (api *api) prepareJobObject(check *Check) (*batchv1.Job, error) {
	jobObj, err := api.readJobObjFromYamlFile(check.CheckType)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Can't read job .yaml file")
		return nil, err
	}

	// Subsitute job's image repository in job.yaml for the one configured for Console.
	currImage := jobObj.Spec.Template.Spec.Containers[0].Image
	splitted := strings.Split(currImage, "/")
	currImgname := splitted[1]
	newImage := fmt.Sprintf("%s/%s", api.scapper.DockerRepoHostPort, currImgname)
	jobObj.Spec.Template.Spec.Containers[0].Image = newImage

	return jobObj, nil
}

func (api *api) getMongoCollectionForCheckType(checkType string) string {
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

func (api *api) readJobObjFromYamlFile(checkType string) (*batchv1.Job, error) {
	jobYamlPath := ""
	if checkType == "kube" {
		jobYamlPath = "/jobs/kube-bench/job.yaml"
	} else if checkType == "docker" {
		jobYamlPath = "/jobs/docker-bench-security/job.yaml"
	} else if checkType == "host" {
		jobYamlPath = "/jobs/host-bench/job.yaml"
	} else {
		return nil, apperror.New(locale.AnError, http.StatusInternalServerError, fmt.Errorf("Unreachable code reached"))
	}

	jobYaml, err := ioutil.ReadFile(jobYamlPath)
	if err != nil {
		return nil, apperror.New(locale.ConfigurationError, http.StatusInternalServerError, fmt.Errorf("Can't read job file: %s", err))
	}

	jobObj := &batchv1.Job{}
	decoder := k8Yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(jobYaml)), 1000)
	err = decoder.Decode(&jobObj)
	if err != nil {
		return nil, apperror.New(locale.ConfigurationError, http.StatusInternalServerError, fmt.Errorf("Can't decode job file: %s", err))

	}
	return jobObj, nil
}

func (api *api) scheduleOneJob(kubeClient *kubernetes.Clientset, check *Check, jobObj *batchv1.Job, targetNodeName string) error {
	jobObj.Spec.Template.Spec.NodeName = targetNodeName

	if jobObj.Labels == nil {
		jobObj.Labels = make(map[string]string)
	}
	jobObj.Labels["CHECK_ID"] = check.CheckUUID.String()
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
		api.scapper.MongoUsername, api.scapper.MongoPassword, api.scapper.MongoEndpoint, api.scapper.MongoDatabase, api.scapper.MongoDatabase)
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
			return apperror.New(locale.KubernetesError, http.StatusInternalServerError, fmt.Errorf("Job already exists, so tried deleting, but: %s", err))
		}

		time.Sleep(time.Second * 10)
		res, err = jobsClient.Create(jobObj)
	}
	if err != nil {
		return apperror.New(locale.KubernetesError, http.StatusInternalServerError, fmt.Errorf("Couldn't schedule job: %s", err))
	}

	jobName := res.ObjectMeta.Name

	logging.GetLogger().Info().
		Str("target-node", jobObj.Spec.Template.Spec.NodeName).
		Str("job-name", jobName).
		Msg("Scheduled SCAP check job")

	return nil
}

func (api *api) mongoAddJobStatusInProgress(ctx context.Context, check *Check, targetNodeName string) error {
	now := time.Now()
	secs := now.Unix()
	entry := JobEntry{
		ID:        primitive.NewObjectIDFromTimestamp(now),
		CheckID:   check.CheckUUID.String(),
		NodeName:  targetNodeName,
		ClusterID: check.ClusterID,
		Status:    "inprogress",
		CreatedAt: secs,
	}

	_, err := api.mongodb.Collection(api.getMongoCollectionForCheckType(check.CheckType)).InsertOne(ctx, entry)
	if err != nil {
		return apperror.New(locale.MongoError, http.StatusInternalServerError, fmt.Errorf("Failed insert to mongo: %s", err))
	}

	return nil
}

func (api *api) mongoJobStatusToFailed(ctx context.Context, check *Check, nodeName, msg string, timeEpochSecs int64) {
	filter := bson.M{"checkId": check.CheckUUID.String(), "nodeName": nodeName}
	// TODO: is there better way to do this using struct annotations?
	update := bson.M{"$set": bson.M{
		"status":     "failed",
		"finishedAt": timeEpochSecs,
		"message":    msg,
	}}
	_, err := api.mongodb.Collection(api.getMongoCollectionForCheckType(check.CheckType)).UpdateOne(ctx, filter, update)
	if err != nil {
		logging.GetLogger().Error().
			Str("checkId", check.CheckUUID.String()).
			Str("nodeName", nodeName).
			Msg("Failed to update mongo entry status to failed")
	}
}

func (api *api) asyncJobStatusUpdater(ctx context.Context, kubeClient *kubernetes.Clientset, check *Check, scheduledNodesCh chan string, maxNumJobs int) {

	// TODO: if console restarts while job is running, that job's events won't be watched.
	// TODO: rethink. Maybe we should have a listener thread all the time and utilize AddFunc
	// to listen to newly created jobs and keep track that way?
	// I think this design is kinda fragile... but I don't have any quick ideas.
	// A better design would be to create a k8s custom resource with a custom controller to manage it.

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
			if isFailed, failedCondition := api.isJobFailed(job); isFailed {
				logging.GetLogger().Info().
					Str("job-name", fmt.Sprintf("%s", job.Name)).
					Msg("Managed job failed")

				thisNodeName := job.Spec.Template.Spec.NodeName
				finishedNodesCh <- thisNodeName

				transTime := failedCondition.LastTransitionTime
				msg := fmt.Sprintf("Message: %s; Reason: %s", failedCondition.Message, failedCondition.Reason)

				mongoCtx, mongoCtxCancel := api.getTimeoutCtx(time.Second * 10)
				api.mongoJobStatusToFailed(mongoCtx, check, thisNodeName, msg, transTime.Unix())
				mongoCtxCancel()
				return
			}

			// some other event happened - pass.
			return
		},
	})

	stop := make(chan struct{})
	defer close(stop)

	logging.GetLogger().Info().
		Str("checkId", check.CheckUUID.String()).
		Msg("Starting to watch for job events")
	kubeInformerFactory.Start(stop)

	// get a list of nodes on which we scheduled a job
	runningNodeNames := []string{}
	for scheduledNodeName := range scheduledNodesCh {
		runningNodeNames = append(runningNodeNames, scheduledNodeName)
	}

	for {
		select {
		case <-ctx.Done():
			logging.GetLogger().Error().Err(ctx.Err()).Msg("Ctx timeout while waiting for jobs to finish, will mark them as timed out")
			// mark remaining runningJobs as timed out.
			now := time.Now().Unix()
			for _, runningNodeName := range runningNodeNames {
				mongoCtx, mongoCtxCancel := api.getTimeoutCtx(time.Second * 10)
				api.mongoJobStatusToFailed(mongoCtx, check, runningNodeName, fmt.Sprintf("Timed out: %s", ctx.Err()), now)
				mongoCtxCancel()
			}
			return

		case finishedJobName := <-finishedNodesCh:
			runningNodeNames = removeElement(finishedJobName, runningNodeNames)
			logging.GetLogger().Info().Int("num-running-jobs-left", len(runningNodeNames)).Msg("Job finished")

			if len(runningNodeNames) == 0 {
				logging.GetLogger().Info().
					Str("checkId", check.CheckUUID.String()).
					Msg("All managed jobs accounted for, done watching for events")
				break
			}
		}
	}

}

func (api *api) isJobFailed(job *batchv1.Job) (bool, *batchv1.JobCondition) {
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

// func (api *api) deleteJobAndPods(kubeClient *kubernetes.Clientset, namespace string, job *batchv1.Job) error {
// 	err := kubeClient.BatchV1().Jobs(namespace).Delete(job.Name, &metav1.DeleteOptions{})
// 	if err != nil {
// 		logging.GetLogger().Error().
// 			Str("job-name", fmt.Sprintf("%s", job.Name)).
// 			Err(err).
// 			Msg("Failed to delete job in k8s")
// 		return fmt.Errorf("Failed to delete job: %s", err)
// 	}

// 	listOpts := metav1.ListOptions{
// 		LabelSelector: labels.Set(job.Spec.Selector.MatchLabels).String(),
// 	}
// 	err = kubeClient.CoreV1().Pods(namespace).DeleteCollection(&metav1.DeleteOptions{}, listOpts)
// 	if err != nil {
// 		return fmt.Errorf("Failed to job's pods: %s", err)
// 	}
// 	return nil
// }

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

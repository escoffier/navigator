package api

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		// TODO: rethink paths, this is bad
		r.Get("/check/{checkType}/{checkID}", api.getScapJob())
		r.Post("/check/{checkType}/cluster/{clusterID}", api.scapCheck())
	}
}

type JobEntry struct {
	ID         primitive.ObjectID `json:"db_id,omitempty" bson:"_id, omitempty"`
	CheckID    string             `json:"check_id" bson:"checkId"`
	NodeName   string             `json:"node_name" bson:"nodeName"`
	Status     string             `json:"status" bson:"status"`
	CreatedAt  int64              `json:"created_at" bson:"createdAt"`
	FinishedAt int64              `json:"finished_at" bson:"finishedAt"`
	Results    string             `json:"results" bson:"results"`
}

// @Summary Get scap results
// @Description Get current scap results for a specific job
// @ID v1-scap-job-get
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param checkID path string true "scap job ID"
// @Router /api/v1/scap/check/{checkType}/{checkID} [get]
func (api *api) getScapJob() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		checkID := chi.URLParam(r, "checkID")
		if checkID == "" {
			response.Bad(w, "checkID param missing")
			return
		}

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			response.Bad(w, "checkType param missing")
			return
		}
		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			response.Bad(w, "invalid checkType param value (allowed: kube/docker/host)")
			return
		}

		// from mongo
		mongoCollection := ""
		if checkType == "kube" {
			mongoCollection = "kube-bench-records"
		} else if checkType == "docker" {
			mongoCollection = "docker-bench-records"
		} else if checkType == "host" {
			mongoCollection = "host-bench-records"
		} else {
			response.InternalError(w, "Unreachable code reached")
			return
		}

		cursor, err := api.mongodb.Collection(mongoCollection).Find(ctx, bson.M{"checkId": checkID})
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}
		defer cursor.Close(ctx)

		var results []JobEntry
		for cursor.Next(ctx) {
			var result JobEntry
			err := cursor.Decode(&result)
			if err != nil {
				response.InternalError(w, err.Error())
				return
			}
			// TODO: pagination
			results = append(results, result)
		}

		err = cursor.Err()
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		response.Ok(w, results)
	}
}

// @Summary Run compliance check on specified cluster
// @Description Run compliance check on specified cluster
// @ID v1-scap-check
// @Produce json
// @Param checkType path string true "kube/docker/host"
// @Param clusterID path string true "cluster ID"
// @Router /api/v1/scap/check/{checkType}/cluster/{clusterID} [post]
func (api *api) scapCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx(time.Second * 60)
		defer cancel()

		checkType := chi.URLParam(r, "checkType")
		if checkType == "" {
			response.Bad(w, "checkType param missing")
			return
		}
		if checkType != "kube" && checkType != "docker" && checkType != "host" {
			response.Bad(w, "invalid checkType param value (allowed: kube/docker/host)")
			return
		}

		clusterID := chi.URLParam(r, "clusterID")
		if clusterID == "" {
			response.Bad(w, "clusterID is not provided")
			return
		}

		// get kube client for this cluster
		cluster, err := api.getClusterFromMongo(ctx, clusterID)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		kubeConfigDecoded, err := b64.StdEncoding.DecodeString(cluster.KubeConfig)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't decode kubeconfig: %s", err))

			return
		}

		kubeClient, err := k8s.CreateK8sClientFromKubeConfig(kubeConfigDecoded)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't create k8s client: %s", err))
			return
		}

		// read job yaml for this check type
		jobYamlPath := ""
		mongoCollection := ""
		if checkType == "kube" {
			jobYamlPath = "/jobs/kube-bench/job.yaml"
			mongoCollection = "kube-bench-records"
		} else if checkType == "docker" {
			jobYamlPath = "/jobs/docker-bench-security/job.yaml"
			mongoCollection = "docker-bench-records"

		} else if checkType == "host" {
			jobYamlPath = "/jobs/host-bench/job.yaml"
			mongoCollection = "host-bench-records"
		} else {
			response.InternalError(w, "Unreachable code reached")
			return
		}

		jobYaml, err := ioutil.ReadFile(jobYamlPath)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't read job file: %s", err))
			return
		}

		jobObj := &batchv1.Job{}
		decoder := k8Yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(jobYaml)), 1000)
		err = decoder.Decode(&jobObj)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't decode job file: %s", err))
			return
		}

		// Subsitute job's image repository in job.yaml for the one configured for Console.
		currImage := jobObj.Spec.Template.Spec.Containers[0].Image
		splitted := strings.Split(currImage, "/")
		currImgname := splitted[1]
		newImage := fmt.Sprintf("%s/%s", api.scapper.DockerRepoHostPort, currImgname)
		jobObj.Spec.Template.Spec.Containers[0].Image = newImage

		// find nodes to schedule check jobs on
		nodes, err := kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
		if err != nil {
			response.InternalError(w, fmt.Sprintf("Can't list nodes in this cluster: %s", err))
			return
		}

		// generate check uuid that will identify results of this run in database
		checkUUID := uuid.NewV4()
		checkEnv := corev1.EnvVar{
			Name:  "CHECK_ID",
			Value: checkUUID.String(),
		}
		jobObj.Spec.Template.Spec.Containers[0].Env = append(jobObj.Spec.Template.Spec.Containers[0].Env, checkEnv)

		// get namespace of this pod - it will be used for scheduled jobs/pods
		namespace := os.Getenv("MY_POD_NAMESPACE")
		if namespace == "" {
			namespace = "default"
		}

		// schedule jobs
		logging.GetLogger().Info().
			Str("check-type", checkType).
			Str("check-uuid", checkUUID.String()).
			Str("namespace", namespace).
			Str("image", jobObj.Spec.Template.Spec.Containers[0].Image).
			Msg("Scheduling SCAP check jobs")

		for _, targetNode := range nodes.Items {
			// TODO: will it scale?
			// What about context timeout? Launching jobs for thousands of nodes may take a while.

			// TODO: resilience. We should save a task to mongo so that in case of Console crash we can restart the check?
			// or do we not care about this since this is a rare operation?
			// Also, this should also clean up all Error and Completed pods.

			jobObjCp := jobObj.DeepCopy()

			jobObjCp.Spec.Template.Spec.NodeName = targetNode.Name

			if jobObjCp.Labels == nil {
				jobObjCp.Labels = make(map[string]string)
			}
			jobObjCp.Labels["CHECK_ID"] = checkUUID.String()
			jobObjCp.Name = fmt.Sprintf("%s-%s", checkUUID.String()[:8], jobObjCp.Name)

			nodeNameEnv := corev1.EnvVar{
				Name:  "NODE_NAME",
				Value: targetNode.Name,
			}
			jobObjCp.Spec.Template.Spec.Containers[0].Env = append(jobObjCp.Spec.Template.Spec.Containers[0].Env, nodeNameEnv)

			// TODO: This should be a secret. There's probably a better way to do this anyways.
			mongoString := fmt.Sprintf("mongodb://%s:%s@%s/%s?authSource=%s",
				api.scapper.MongoUsername, api.scapper.MongoPassword, api.scapper.MongoEndpoint, api.scapper.MongoDatabase, api.scapper.MongoDatabase)
			mongoStringEnv := corev1.EnvVar{
				Name:  "MONGO_STRING",
				Value: mongoString,
			}
			jobObjCp.Spec.Template.Spec.Containers[0].Env = append(jobObjCp.Spec.Template.Spec.Containers[0].Env, mongoStringEnv)

			jobObjCp.Name = fmt.Sprintf("%s-%s", jobObjCp.Name, targetNode.Name)

			jobsClient := kubeClient.BatchV1().Jobs(namespace)
			res, err := jobsClient.Create(jobObjCp)
			// HACK
			if k8serrors.IsAlreadyExists(err) {
				err = jobsClient.Delete(jobObjCp.Name, &metav1.DeleteOptions{})
				if err != nil {
					response.InternalError(w, fmt.Sprintf("Job already exists, so tried deleting, but: %s", err))
					return
				}

				time.Sleep(time.Second * 10)
				res, err = jobsClient.Create(jobObjCp)
			}
			if err != nil {
				response.InternalError(w, fmt.Sprintf("Couldn't schedule job: %s", err))
				return
			}

			jobName := res.ObjectMeta.Name

			now := time.Now()
			secs := now.Unix()
			entry := JobEntry{
				ID:        primitive.NewObjectIDFromTimestamp(now),
				CheckID:   checkUUID.String(),
				NodeName:  targetNode.Name,
				Status:    "scheduled",
				CreatedAt: secs,
			}
			// TODO: Potential race condition: we are inserting to mongo after scheduling the job (which upserts to mongo).
			// However I don't see a better way to do this right now.
			_, err = api.mongodb.Collection(mongoCollection).InsertOne(ctx, entry)
			if err != nil {
				response.InternalError(w, err.Error())
				return
			}

			logging.GetLogger().Info().
				Str("target-node", jobObjCp.Spec.Template.Spec.NodeName).
				Str("job-name", jobName).
				Msg("Scheduled SCAP check job")
		}

		response.Ok(w, checkUUID.String())
	}
}

// @Summary Tell scap to check
// @Description Tell scap to check
// @ID v1-scap-check
// @Produce json
// @Router /api/v1/scap/check [post]
// func (api *api) scapcheck() http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		task := &model.ScapTask{
// 			ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
// 			ScannerType: "kubebench_all",
// 			Status:      model.ScannerStatusReady,
// 			CreatedAt:   time.Now().Unix(),
// 		}

// 		ctx, cancel := api.getTimeoutCtx()
// 		defer cancel()
// 		_, err := api.mongodb.Collection(model.ScapTasksCollection).
// 			InsertOne(ctx, task)
// 		if err != nil {
// 			response.InternalError(w, err.Error())
// 			return
// 		}

// 		response.Ok(w, task)
// 	}
// }

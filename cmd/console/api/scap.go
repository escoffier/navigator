package api

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"

	"go.mongodb.org/mongo-driver/bson"
	batchv1 "k8s.io/api/batch/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"
)

func (api *api) scap() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/task/{taskID}", api.getScapTask())
		r.Post("/check/{checkType}/cluster/{clusterID}", api.scapCheck())
	}
}

// @Summary Get a scap task by scaptask ID
// @Description Get a scap task
// @ID v1-scap-task-get
// @Produce json
// @Param taskID path string true "scap task ID"
// @Router /api/v1/scap/task/{taskID} [get]
func (api *api) getScapTask() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get ObjectID
		taskObjectID, err := getTaskObjectIDFromURL(r)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		// from mongo
		var result model.ScapTask
		err = api.mongodb.Collection(model.ScapTasksCollection).FindOne(
			ctx, bson.M{"_id": taskObjectID}).Decode(&result)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}

		response.Ok(w, result)
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
	// type resp struct {
	// 	ClusterID string `json:"clusterID"`
	// }
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
		if checkType == "kube" {
			jobYamlPath = "/jobs/kube-bench/job.yaml"
		} else if checkType == "docker" {
			jobYamlPath = "/jobs/docker-bench-security/job.yaml"
		} else {
			response.InternalError(w, "TODO host SCAP")
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

		// schedule job
		jobsClient := kubeClient.BatchV1().Jobs("default")
		res, err := jobsClient.Create(jobObj)

		// HACK
		if k8serrors.IsAlreadyExists(err) {
			err = jobsClient.Delete(jobObj.Name, &metav1.DeleteOptions{})
			if err != nil {
				response.InternalError(w, fmt.Sprintf("Job already exists, so tried deleting, but: %s", err))
				return
			}

			time.Sleep(time.Second * 10)
			res, err = jobsClient.Create(jobObj)
		}

		if err != nil {
			response.InternalError(w, fmt.Sprintf("Failed to schedule job: %s", err))
			return
		}

		jobName := res.ObjectMeta.Name
		fmt.Println("jobName: ", jobName)
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

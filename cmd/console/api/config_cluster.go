package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	b64 "encoding/base64"

	"github.com/go-chi/chi"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	clusterCol = "cluster"
	nameSpace  = "vegeta"
)

type cluster struct {
	ID          primitive.ObjectID `json:"id" bson:"_id, omitempty"`
	ClusterName string             `json:"name" bson:"name"`
	KubeConfig  string             `json:"config" bson:"config"`
	ClusterType int                `json:"type" bson:"type"` // Kubenetes 1, OpenShift 2, Docker 3
}

// @Summary Get single cluster information
// @Description Get single cluster information
// @ID v1-config-cluster-get
// @Produce json
// @Success 200 {object} cluster
// @Success 400 {string} string "clusterID is not provided"
// @Param clusterID path string true "clusterID"
// @Router /api/v1/config/cluster/{clusterID} [get]
func (api *api) getCluster() http.HandlerFunc {
	type resp struct {
		Cluster cluster `json:"cluster"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		clusterID := chi.URLParam(r, "clusterID")

		if clusterID == "" {
			response.Bad(w, "clusterID is not provided")
			return
		}

		queryCluster, err := api.getClusterFromMongo(ctx, clusterID)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		response.Ok(w, response.WithItem(queryCluster))
	}
}

func (api *api) getClusterFromMongo(ctx context.Context, clusterID string) (*cluster, error) {
	var queryCluster cluster
	clusterObjectID, err := primitive.ObjectIDFromHex(clusterID)
	if err != nil {
		return nil, err
	}
	filter := bson.M{"_id": clusterObjectID}

	queryResult := api.mongodb.Collection(clusterCol).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		return nil, fmt.Errorf("MongoDB: %s", queryResult.Err())
	}

	err = queryResult.Decode(&queryCluster)
	if err != nil {
		return nil, fmt.Errorf("MongoDB: %s", err)
	}
	return &queryCluster, nil
}

// @Summary Get all clusters information
// @Description Get all cluster information
// @ID v1-config-cluster-get-all
// @Produce json
// @Param offset query int false "from offset"
// @Param limit query int false "returned data limit"
// @Router /api/v1/config/clusters [get]
func (api *api) listClusters() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var clusters []cluster

		filter := bson.D{}

		ctx, cancel := api.getTimeoutCtx(15 * time.Second)
		defer cancel()
		offset, limit := api.getOffsetAndLimit(r)

		opts := options.Find()
		opts.SetSkip(offset)
		opts.SetLimit(limit)

		coll := api.mongodb.Collection(clusterCol)

		cur, err := coll.Find(ctx, filter, opts)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("MongoDB: %s", err))
			return
		}
		defer cur.Close(ctx)

		for cur.Next(ctx) {
			//Create a value into which the single document can be decoded
			var elem cluster
			err := cur.Decode(&elem)
			if err != nil {
				response.InternalError(w, fmt.Sprintf("MongoDB: %s", err))
				return
			}
			clusters = append(clusters, elem)
		}

		docNum, err := coll.CountDocuments(ctx, filter)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("MongoDB: %s", err))
			return
		}

		response.Ok(w,
			response.WithItems(clusters),
			response.WithTotalItems(docNum),
			response.WithItemsPerPage(limit),
			response.WithStartIndex(offset))
	}
}

// @Summary Update single cluster information
// @Description Update single cluster information
// @ID v1-config-cluster-put
// @Produce json
// @Param clusterID path string true "clusterID"
// @Param name body string true "clusterID"
// @Param config body string true "kubeConfig -- base64String"
// @Param type body int true "Kubenetes 1, OpenShift 2, Docker 3"
// @Router /api/v1/config/cluster/{clusterID} [put]
func (api *api) updateCluster() http.HandlerFunc {
	type resp struct {
		Message string `json:"message"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		clusterID := chi.URLParam(r, "clusterID")
		if clusterID == "" {
			response.Bad(w, "clusterID is not provided")
			return
		}

		var upCluster cluster
		clusterObjectID, err := primitive.ObjectIDFromHex(clusterID)
		if err != nil {
			response.Bad(w, fmt.Sprintf("Cluster API Request: %s", err))
			return
		}

		err = decodeJSONBody(w, r, &upCluster)
		if err != nil {
			response.Bad(w, fmt.Sprintf("Cluster API Request: %s", err))
			return
		}
		// No sure the this api can work under Openshift
		if upCluster.ClusterType < 3 {
			//valid vegeta Namespace is there and have the auth to view the pods

			err = checkKubeConfigValid(upCluster.KubeConfig)
			if err != nil {
				response.InternalError(w, err.Error())
				return
			}
		}

		filter := bson.M{"_id": clusterObjectID}
		upCluster.ID = clusterObjectID
		update := bson.M{"$set": upCluster}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		_, err = api.mongodb.Collection(clusterCol).UpdateOne(ctx, filter, update)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("MongoDB: %s", err))
			return
		}
		response.Ok(w, response.WithItem(resp{
			Message: "Successful updated",
		}))
	}
}

// @Summary Add new cluster
// @Description Add new cluster
// @ID v1-config-cluster-post
// @Produce json
// @Param name body string true "clusterName"
// @Param config body string true "kubeConfig -- base64String "
// @Param type body int true "Kubenetes 1, OpenShift 2, Docker 3"
// @Router /api/v1/config/cluster [post]
func (api *api) addCluster() http.HandlerFunc {
	type resp struct {
		ClusterID string `json:"clusterID"`
	}
	type param struct {
		ClusterName string `json:"name" bson:"name"`
		KubeConfig  string `json:"config" bson:"config"`
		ClusterType int    `json:"type" bson:"type"` // Kubenetes 1, OpenShift 2, Docker 3
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var param param

		err := decodeJSONBody(w, r, &param)
		if err != nil {
			response.Bad(w, fmt.Sprintf("Cluster API Request: %s", err))
			return
		}

		if param.ClusterType > 3 || param.ClusterType < 1 {
			response.Bad(w, "ClusterType is out range")
			return
		}

		newCluster := &cluster{
			ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
			ClusterName: param.ClusterName,
			KubeConfig:  param.KubeConfig,
			ClusterType: param.ClusterType,
		}

		// No sure the this api can work under Openshift
		if newCluster.ClusterType < 3 {
			//valid vegeta Namespace is there and have the auth to view the pods

			err = checkKubeConfigValid(newCluster.KubeConfig)
			if err != nil {
				response.InternalError(w, err.Error())
				return
			}
		}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()
		collection := api.mongodb.Collection(clusterCol)

		// find if this cluster already there
		filter := bson.M{"name": newCluster.ClusterName}

		queryResult := collection.FindOne(ctx, filter)

		//if find the record then return
		if queryResult.Err() == nil {
			response.Bad(w, "This cluster is already in the db")
			return
		}

		insertResult, err := collection.InsertOne(ctx, newCluster)
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}
		response.Ok(w, response.WithItem(resp{
			ClusterID: fmt.Sprintf("%v", insertResult.InsertedID),
		}))
	}
}

// @Summary Delete a cluster
// @Description Delete a cluster by cluster ID
// @ID v1-config-cluster-delete
// @Produce json
// @Param clusterID path string true "clusterID"
// @Success 200 {string} string "MongoDB DeletedCount"
// @Router /api/v1/config/cluster/{clusterID} [delete]
func (api *api) delCluster() http.HandlerFunc {
	type resp struct {
		Message string `json:"message"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		clusterID := chi.URLParam(r, "clusterID")
		if clusterID == "" {
			response.Bad(w, "clusterID is not provided")
			return
		}

		clusterObjectID, err := primitive.ObjectIDFromHex(clusterID)
		if err != nil {
			response.Bad(w, err.Error())
			return
		}

		filter := bson.M{"_id": clusterObjectID}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		delResult, err := api.mongodb.Collection(clusterCol).DeleteOne(ctx, filter)
		if err != nil {
			response.InternalError(w, fmt.Sprintf("MongoDB: %s", err))
			return
		}
		response.Ok(w, response.WithItem(resp{
			Message: fmt.Sprintf("MongoDB DeletedCount: %d", delResult.DeletedCount),
		}))
	}
}

func checkKubeConfigValid(kubeConfig string) error {
	//valid vegeta Namespace is there and have the auth to view the pods
	kubeconfig, err := b64.StdEncoding.DecodeString(kubeConfig)
	if err != nil {
		return errors.New((fmt.Sprintf("Can't decoding the kubeconfig: %s", err)))
	}

	kubeClient, err := k8s.CreateK8sClientFromKubeConfig(kubeconfig)
	if err != nil {
		return errors.New((fmt.Sprintf("Cluster API Request: %s", err)))
	}
	_, err = kubeClient.CoreV1().Namespaces().Get(nameSpace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Maybe namespace doesn't exist or no authorization?: %s", err)
	}
	_, err = kubeClient.CoreV1().Pods(nameSpace).List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Maybe no pod view authorization?: %s", err)
	}
	return nil
}

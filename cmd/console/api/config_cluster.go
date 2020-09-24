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
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/locale"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
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

		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		queryCluster, err := api.getClusterFromMongo(ctx, clusterObjectID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't get cluster from mongo")
			apperror.RespondWithSuggested(w, r, err)
			return
		}

		response.Ok(w, response.WithItem(queryCluster))
	}
}

func getClusterIDFromURL(r *http.Request) (primitive.ObjectID, error) {
	clusterID := chi.URLParam(r, "clusterID")
	if clusterID == "" {
		return primitive.NilObjectID, errors.New("clusterID is not provided")
	}
	return primitive.ObjectIDFromHex(clusterID)
}

func (api *api) getClusterFromMongo(ctx context.Context, clusterObjectID primitive.ObjectID) (*cluster, error) {
	var queryCluster cluster
	filter := bson.M{"_id": clusterObjectID}

	queryResult := api.mongodb.Collection(clusterCol).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, apperror.New(locale.MongoError, http.StatusNotFound, fmt.Errorf("Document not found: %s", queryResult.Err()))
		}
		return nil, apperror.New(locale.MongoError, http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %s", queryResult.Err()))
	}

	err := queryResult.Decode(&queryCluster)
	if err != nil {
		return nil, apperror.New(locale.MongoError, http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %s", queryResult.Err()))
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
			logging.GetLogger().Error().Err(err).Msg("Couldn't find documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		defer cur.Close(ctx)

		for cur.Next(ctx) {
			//Create a value into which the single document can be decoded
			var elem cluster
			err := cur.Decode(&elem)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Couldn't decode document")
				response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
				return
			}
			clusters = append(clusters, elem)
		}

		docNum, err := coll.CountDocuments(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't count documents")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
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
		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		var upCluster cluster

		err = decodeJSONBody(w, r, &upCluster)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Failed to decode json")
			response.Bad(w, response.WithMessage(locale.Error(locale.MalformedRequestError, r)))
			return
		}

		// No sure the this api can work under Openshift
		if upCluster.ClusterType < 3 {
			kubeClient, err := kubeClientFromB64KubeConfig(upCluster.KubeConfig)
			if err != nil {
				logging.GetLogger().Info().Err(err).Msg("Failed to create kube client")
				response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("config", ""))
				return
			}

			err = checkKubeClientConnection(kubeClient)
			if err != nil {
				logging.GetLogger().Info().Err(err).Msg("Failed to connect to k8s cluster")
				response.InternalError(w, response.WithMessage(locale.Error(locale.KubernetesError, r)), response.WithSuberror("config", ""))
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
			logging.GetLogger().Error().Err(err).Msg("Couldn't update document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
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
			logging.GetLogger().Info().Err(err).Msg("Failed to decode json")
			response.Bad(w, response.WithMessage(locale.Error(locale.MalformedRequestError, r)))
			return
		}

		if param.ClusterType > 3 || param.ClusterType < 1 {
			logging.GetLogger().Info().Err(err).Msg("ClusterType is out range")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("type", ""))
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
			kubeClient, err := kubeClientFromB64KubeConfig(newCluster.KubeConfig)
			if err != nil {
				logging.GetLogger().Info().Err(err).Msg("Failed to create kube client")
				response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("config", ""))
				return
			}

			err = checkKubeClientConnection(kubeClient)
			if err != nil {
				logging.GetLogger().Info().Err(err).Msg("Failed to connect to k8s cluster")
				response.InternalError(w, response.WithMessage(locale.Error(locale.KubernetesError, r)), response.WithSuberror("config", ""))
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
			logging.GetLogger().Info().Err(err).Msg("Cluster with this name already exists")
			response.Conflict(w, response.WithMessage(locale.Error(locale.ClusterAlreadyExists, r)))
			return
		}

		insertResult, err := collection.InsertOne(ctx, newCluster)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't insert document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
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
		clusterObjectID, err := getClusterIDFromURL(r)
		if err != nil {
			logging.GetLogger().Info().Err(err).Msg("Couldn't read ClusterID")
			response.Bad(w, response.WithMessage(locale.Error(locale.FieldError, r)), response.WithSuberror("clusterID", ""))
			return
		}

		filter := bson.M{"_id": clusterObjectID}

		ctx, cancel := api.getTimeoutCtx()
		defer cancel()

		delResult, err := api.mongodb.Collection(clusterCol).DeleteOne(ctx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Couldn't delete document")
			response.InternalError(w, response.WithMessage(locale.Error(locale.MongoError, r)))
			return
		}
		response.Ok(w, response.WithItem(resp{
			Message: fmt.Sprintf("MongoDB DeletedCount: %d", delResult.DeletedCount),
		}))
	}
}

func kubeClientFromB64KubeConfig(kubeConfig string) (*kubernetes.Clientset, error) {
	kubeconfig, err := b64.StdEncoding.DecodeString(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Can't decode kubeconfig: %s", err)
	}

	kubeClient, err := k8s.CreateK8sClientFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Cluster API Request: %s", err)
	}
	return kubeClient, nil
}

func checkKubeClientConnection(kubeClient *kubernetes.Clientset) error {
	_, err := kubeClient.CoreV1().Namespaces().Get(nameSpace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Maybe namespace doesn't exist or no authorization?: %s", err)
	}
	_, err = kubeClient.CoreV1().Pods(nameSpace).List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Maybe no pod view authorization?: %s", err)
	}
	return nil
}

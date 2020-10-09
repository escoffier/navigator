package cluster

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	clusterCol = "cluster"
)

type ClusterService struct {
	mongodb *mongo.Database
}

func NewClusterService(
	mongodb *mongo.Database,
) *ClusterService {
	return &ClusterService{
		mongodb: mongodb,
	}
}

func (s *ClusterService) GetCluster(ctx context.Context, clusterObjectID primitive.ObjectID) (*model.Cluster, error) {
	var queryCluster model.Cluster
	filter := bson.M{"_id": clusterObjectID}

	queryResult := s.mongodb.Collection(clusterCol).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err := queryResult.Decode(&queryCluster)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	return &queryCluster, nil
}

func (s *ClusterService) AddCluster(ctx context.Context, clusterName string, kubeConfig string) (primitive.ObjectID, error) {
	newCluster := &model.Cluster{
		ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
		ClusterName: clusterName,
		KubeConfig:  kubeConfig,
	}

	kubeClient, err := k8s.KubeClientFromB64KubeConfig(newCluster.KubeConfig)
	if err != nil {
		return primitive.NilObjectID, NewKubernetesError(http.StatusBadRequest, fmt.Errorf("Failed to create kube client from config: %w", err), Suberror{"config", ""})
	}
	err = k8s.CheckKubeClientConnection(kubeClient)
	if err != nil {
		return primitive.NilObjectID, NewKubernetesError(http.StatusBadRequest, fmt.Errorf("Kube client connection check failed: %w", err))
	}

	collection := s.mongodb.Collection(clusterCol)

	// find if this cluster already there
	filter := bson.M{"name": newCluster.ClusterName}

	queryResult := collection.FindOne(ctx, filter)

	//if find the record then return
	if queryResult.Err() == nil {
		return primitive.NilObjectID, NewClusterAlreadyExists(http.StatusBadRequest, fmt.Errorf("Cluster already exists: %w", queryResult.Err()))
	}

	insertResult, err := collection.InsertOne(ctx, newCluster)
	if err != nil {
		return primitive.NilObjectID, err
	}
	id, ok := insertResult.InsertedID.(primitive.ObjectID)
	if !ok {
		return primitive.NilObjectID, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document ID: %w", queryResult.Err()))
	}
	return id, nil
}

func (s *ClusterService) ListClusters(ctx context.Context, offset int64, limit int64) ([]model.Cluster, int64, error) {
	filter := bson.D{}
	var clusters []model.Cluster
	opts := options.Find()
	opts.SetSkip(offset)
	opts.SetLimit(limit)

	coll := s.mongodb.Collection(clusterCol)

	cur, err := coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cur.Close(ctx)

	for cur.Next(ctx) {
		//Create a value into which the single document can be decoded
		var elem model.Cluster
		err := cur.Decode(&elem)
		if err != nil {
			return nil, 0, err
		}
		clusters = append(clusters, elem)
	}

	docNum, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	return clusters, docNum, err
}

func (s *ClusterService) UpdateCluster(ctx context.Context, clusterObjectID primitive.ObjectID, upCluster *model.Cluster) (*model.Cluster, error) {
	kubeClient, err := k8s.KubeClientFromB64KubeConfig(upCluster.KubeConfig)
	if err != nil {
		return nil, err
	}

	err = k8s.CheckKubeClientConnection(kubeClient)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"_id": clusterObjectID}
	upCluster.ID = clusterObjectID
	update := bson.M{"$set": upCluster}

	_, err = s.mongodb.Collection(clusterCol).UpdateOne(ctx, filter, update)

	queryResult := s.mongodb.Collection(clusterCol).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	var queryCluster model.Cluster
	err = queryResult.Decode(&queryCluster)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	return &queryCluster, nil
}

func (s *ClusterService) DeleteCluster(ctx context.Context, clusterObjectID primitive.ObjectID) (*mongo.DeleteResult, error) {
	filter := bson.M{"_id": clusterObjectID}

	res, err := s.mongodb.Collection(clusterCol).DeleteOne(ctx, filter)
	if err != nil {
		return nil, err
	}
	return res, nil
}

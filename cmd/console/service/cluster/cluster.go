package cluster

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/cleanup"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/onlinevulns"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ClusterService struct {
	mongodb        *mongo.Database
	onlineVulnsSvc *onlinevulns.OnlineVulnsService
	cleanupService *cleanup.CleanupService
}

func NewClusterService(
	mongodb *mongo.Database,
	onlineVulnsSvc *onlinevulns.OnlineVulnsService,
	cleanupService *cleanup.CleanupService,
) *ClusterService {
	return &ClusterService{
		mongodb:        mongodb,
		onlineVulnsSvc: onlineVulnsSvc,
		cleanupService: cleanupService,
	}
}

func (s *ClusterService) GetCluster(ctx context.Context, clusterObjectID primitive.ObjectID, onlyActive bool) (*model.Cluster, error) {
	var queryCluster model.Cluster

	filter := bson.M{
		"_id": clusterObjectID,
	}
	if onlyActive {
		filter = bson.M{"_id": clusterObjectID, "deleted_at": bson.M{"$exists": false}}
	}

	queryResult := s.mongodb.Collection(model.ClusterCollection.String()).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewClusterDoesntExistError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
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
		CreatedAt:   time.Now(),
	}

	kubeClient, err := k8s.KubeClientFromB64KubeConfig(newCluster.KubeConfig)
	if err != nil {
		return primitive.NilObjectID, NewKubernetesError(http.StatusBadRequest, fmt.Errorf("Failed to create kube client from config: %w", err), Suberror{"config", ""})
	}
	err = k8s.CheckKubeClientConnection(kubeClient)
	if err != nil {
		return primitive.NilObjectID, NewKubernetesError(http.StatusBadRequest, fmt.Errorf("Kube client connection check failed: %w", err))
	}

	collection := s.mongodb.Collection(model.ClusterCollection.String())

	var id primitive.ObjectID

	err = s.mongodb.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		var sessionError error
		sessionError = sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		sessionCommitter := repository.MongoSessionCommitter(sessionContext, &sessionError)
		defer sessionCommitter()

		// find if this cluster already there
		filter := bson.M{"name": newCluster.ClusterName, "deleted_at": bson.M{"$exists": false}}

		var id primitive.ObjectID
		queryResult := collection.FindOne(sessionContext, filter)

		//if find the record then return
		if queryResult.Err() == nil {
			sessionError = queryResult.Err()
			return NewClusterAlreadyExists(http.StatusBadRequest, fmt.Errorf("Cluster already exists: %w", sessionError))
		}
		var insertResult *mongo.InsertOneResult
		insertResult, sessionError = collection.InsertOne(sessionContext, newCluster)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", sessionError))
		}
		id, ok := insertResult.InsertedID.(primitive.ObjectID)
		if !ok {
			sessionError = fmt.Errorf("Couldn't parse document ID: %v", id)
			return NewMongoError(http.StatusInternalServerError, sessionError)
		}

		// TODO: maybe a hook mechanism so cluster service doesn't depend on onlinevulns service?
		// TODO: doesn't support multiple clusters yet.
		err = s.onlineVulnsSvc.OnKubeConfigUpdate(sessionContext, kubeClient)
		if err != nil {
			return err
		}

		restConfig, err := k8s.GetRestConfigFromKubeConfig(newCluster.KubeConfig)
		if err != nil {
			return err
		}

		s.cleanupService.OnKubeConfigUpdate(kubeClient, restConfig)
		return nil
	})
	if err != nil {
		return primitive.NilObjectID, err
	}
	return id, nil
}

func (s *ClusterService) ListClusters(ctx context.Context, offset int64, limit int64) ([]model.Cluster, int64, error) {
	filter := bson.M{"deleted_at": bson.M{"$exists": false}}
	var clusters []model.Cluster
	opts := options.Find()
	opts.SetSkip(offset)
	opts.SetLimit(limit)

	coll := s.mongodb.Collection(model.ClusterCollection.String())

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
	filter := bson.M{"_id": clusterObjectID, "deleted_at": bson.M{"$exists": false}}

	var queryCluster model.Cluster

	err := s.mongodb.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		var sessionError error
		sessionError = sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		sessionCommitter := repository.MongoSessionCommitter(sessionContext, &sessionError)
		defer sessionCommitter()

		queryResult := s.mongodb.Collection(model.ClusterCollection.String()).FindOne(sessionContext, filter)
		if queryResult.Err() != nil {
			sessionError = queryResult.Err()
			if sessionError == mongo.ErrNoDocuments {
				return NewClusterDoesntExistError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", sessionError))
		}

		sessionError = queryResult.Decode(&queryCluster)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", sessionError))
		}

		if queryCluster.KubeConfig != upCluster.KubeConfig {
			return NewClusterError(http.StatusBadRequest, fmt.Errorf("Cannot update cluster's kube config"))
		}
		queryCluster.ClusterName = upCluster.ClusterName

		update := bson.M{"$set": queryCluster}

		_, sessionError = s.mongodb.Collection(model.ClusterCollection.String()).UpdateOne(sessionContext, filter, update)
		if sessionError != nil {
			if sessionError == mongo.ErrNoDocuments {
				return NewClusterDoesntExistError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", sessionError))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &queryCluster, nil
}

func (s *ClusterService) DeleteCluster(ctx context.Context, clusterObjectID primitive.ObjectID) (int64, error) {
	var res int64
	err := s.mongodb.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		var sessionError error
		sessionError = sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		sessionCommitter := repository.MongoSessionCommitter(sessionContext, &sessionError)
		defer sessionCommitter()

		filter := bson.M{"_id": clusterObjectID, "deleted_at": bson.M{"$exists": false}}

		queryResult := s.mongodb.Collection(model.ClusterCollection.String()).FindOne(sessionContext, filter)
		if queryResult.Err() != nil {
			sessionError = queryResult.Err()
			if sessionError == mongo.ErrNoDocuments {
				return NewClusterDoesntExistError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", sessionError))
		}
		var queryCluster model.Cluster
		sessionError = queryResult.Decode(&queryCluster)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", sessionError))
		}

		queryCluster.DeletedAt = time.Now()
		queryCluster.HistoricisedTimestamp = time.Now()
		update := bson.M{"$set": queryCluster}

		var result *mongo.UpdateResult
		result, sessionError = s.mongodb.Collection(model.ClusterCollection.String()).UpdateOne(sessionContext, filter, update)
		if sessionError != nil {
			if sessionError == mongo.ErrNoDocuments {
				return NewClusterDoesntExistError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't remove document: %w", sessionError))
		}

		sessionError = s.onlineVulnsSvc.OnKubeConfigUpdate(sessionContext, nil)
		if sessionError != nil {
			return sessionError
		}
		s.cleanupService.OnKubeConfigUpdate(nil, nil)

		res = result.MatchedCount
		return nil
	})
	if err != nil {
		return 0, err
	}

	return res, nil
}

package cluster

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/kubemonitor"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	rcache "gitlab.com/piccolo_su/vegeta/pkg/cache"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"k8s.io/client-go/kubernetes"
)

var (
	instance *ClusterService
	once     sync.Once
)

type ClusterService struct {
	mongodb       *mongotools.DatabaseWrapper
	postgreDB     *rdbtools.GormWrapper
	clustersCache *rcache.ClustersCache
}

func Init(
	ctx context.Context,
	postgreDB *rdbtools.GormWrapper,
	mongodb *mongotools.DatabaseWrapper,
	redisClient *redis.Client,
) error {
	once.Do(func() {
		instance = &ClusterService{
			mongodb:       mongodb,
			postgreDB:     postgreDB,
			clustersCache: rcache.NewClustersCache(ctx, mongodb, redisClient),
		}
	})

	return nil
}

func Get(ctx context.Context) (*ClusterService, bool) {
	return instance, instance != nil
}

func (s *ClusterService) GetCluster(ctx context.Context, clusterObjectID primitive.ObjectID, onlyActive bool) (*model.Cluster, error) {
	var queryCluster model.Cluster

	filter := bson.M{
		"_id": clusterObjectID,
	}
	if onlyActive {
		filter = bson.M{"_id": clusterObjectID, "deleted_at": bson.M{"$exists": false}}
	}

	opts := options.FindOne().SetMaxTime(500 * time.Millisecond)
	queryResult := s.mongodb.Get().Collection(model.ClusterCollection.String()).FindOne(ctx, filter, opts)
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

	collection := s.mongodb.Get().Collection(model.ClusterCollection.String())

	var id primitive.ObjectID

	err = s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

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
		inResService, _ := assetsSvc.GetAssetsInResourcesService(ctx)
		kbmSvc, _ := kubemonitor.Get(ctx)
		resSvc, _ := assetsSvc.GetResourcesService(ctx)
		watcher, werr := assetsSvc.Watcher(s.postgreDB, inResService, kbmSvc, resSvc)
		if werr != nil {
			return werr
		}
		err = watcher.StartsToWatch(sessionContext, map[string]*kubernetes.Clientset{
			"default": kubeClient,
		})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return primitive.NilObjectID, err
	}

	err = s.clustersCache.RefreshCache()
	if err != nil {
		return primitive.NilObjectID, NewAnError(
			http.StatusInternalServerError, fmt.Errorf("Couldn't refresh cache: %w", err))
	}

	return id, nil
}

func (s *ClusterService) ListClusters(ctx context.Context, offset int64, limit int64) ([]model.Cluster, int64, error) {
	clusterIds, docNum, err := s.clustersCache.GetItems(ctx, offset, limit)
	if err != nil {
		return nil, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Failed to get results from cache: %w", err))
	}

	items := make([]model.Cluster, len(clusterIds))

	ids := make([]primitive.ObjectID, len(clusterIds))
	for i := range clusterIds {
		ids[i] = clusterIds[i].ID
	}

	filter := bson.D{{"_id", bson.D{{"$in", ids}}}}
	opts := options.Find()
	opts.SetMaxTime(time.Second * 10)
	opts.SetSort(bson.D{{"createdAt", util.SortOrderToInt("desc")}})

	coll := s.mongodb.Get().Collection(model.ClusterCollection.String())
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*2)
	defer mongoCtxCancel()

	cur, err := coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find documents: %w", err))
	}
	defer cur.Close(mongoCtx)
	var clusterNo int = 0
	for cur.Next(mongoCtx) {
		var cluster model.Cluster
		err := cur.Decode(&cluster)
		if err != nil {
			return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}

		items[clusterNo] = cluster
		clusterNo++
	}
	err = cur.Err()
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Mongo cursor error: %w", err))
	}

	return items, docNum, nil
}

func (s *ClusterService) UpdateCluster(ctx context.Context, clusterObjectID primitive.ObjectID, upCluster *model.Cluster) (*model.Cluster, error) {
	filter := bson.M{"_id": clusterObjectID, "deleted_at": bson.M{"$exists": false}}

	var queryCluster model.Cluster

	err := s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		queryResult := s.mongodb.Get().Collection(model.ClusterCollection.String()).FindOne(sessionContext, filter)
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

		_, sessionError = s.mongodb.Get().Collection(model.ClusterCollection.String()).UpdateOne(sessionContext, filter, update)
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
	err := s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		filter := bson.M{"_id": clusterObjectID, "deleted_at": bson.M{"$exists": false}}

		queryResult := s.mongodb.Get().Collection(model.ClusterCollection.String()).FindOne(sessionContext, filter)
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
		result, sessionError = s.mongodb.Get().Collection(model.ClusterCollection.String()).UpdateOne(sessionContext, filter, update)
		if sessionError != nil {
			if sessionError == mongo.ErrNoDocuments {
				return NewClusterDoesntExistError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't remove document: %w", sessionError))
		}

		resSvc, _ := assetsSvc.GetResourcesService(ctx)
		inResService, _ := assetsSvc.GetAssetsInResourcesService(ctx)
		kbmSvc, _ := kubemonitor.Get(ctx)
		watcher, werr := assetsSvc.Watcher(s.postgreDB, inResService, kbmSvc, resSvc)
		if werr != nil {
			return werr
		}
		sessionError = watcher.StopWatch(sessionContext, []string{"default"})
		if sessionError != nil {
			return sessionError
		}

		res = result.MatchedCount
		return nil
	})
	if err != nil {
		return 0, err
	}

	err = s.clustersCache.RefreshCache()
	if err != nil {
		return 0, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't refresh cache: %w", err))
	}

	return res, nil
}

package cache

import (
	"context"
	"fmt"
	"net/http"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ClustersCache struct {
	ctx     context.Context
	mongodb *mongo.Database
	ch      *util.CacheHelper
}

func NewClustersCache(
	ctx context.Context,
	mongodb *mongo.Database,
	redisClient *redis.Client,
) *ClustersCache {

	c := &ClustersCache{
		ctx:     ctx,
		mongodb: mongodb,
	}
	c.ch = util.NewCacheHelper(
		ctx,
		"Clusters",
		redisClient,
		c.getClustersNewestEntryTimestamp,
		util.TimestampKey,
	)
	c.ch.AddToRegistry(c.getClustersData)
	return c
}

func (c *ClustersCache) getClustersNewestEntryTimestamp() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, util.MongoTimeout)
	defer cancel()
	filter := bson.M{}

	findOptions := options.FindOne()
	findOptions.SetSort(bson.D{{"created_at", -1}})

	singleResult := c.mongodb.Collection(model.ClusterCollection.String()).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return -1, nil
		}
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
	}

	var cluster model.Cluster
	err := singleResult.Decode(&cluster)
	if err != nil {
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
	}

	createdAt := cluster.CreatedAt.Unix()

	findOptions = options.FindOne()
	findOptions.SetSort(bson.D{{"deleted_at", -1}})

	singleResult = c.mongodb.Collection(model.ClusterCollection.String()).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return -1, nil
		}
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
	}

	err = singleResult.Decode(&cluster)
	if err != nil {
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
	}

	deletedAt := cluster.DeletedAt.Unix()

	if createdAt > deletedAt {
		return createdAt, nil
	}
	return deletedAt, nil
}

func (c *ClustersCache) getClustersData() ([]model.CacheEntry, error) {
	filter := bson.M{"deleted_at": bson.M{"$exists": false}}
	findOptions := options.FindOptions{}
	findOptions.SetSort(bson.D{{"createdAt", -1}})

	clusterIds, err := dataToIds(c.ctx, filter, &findOptions, c.mongodb.Collection(model.ClusterCollection.String()))
	if err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Could not get ids to cache: %w", err))
	}
	return clusterIds, nil
}

func (c *ClustersCache) GetItems(ctx context.Context, offset int64, limit int64) ([]model.CacheEntry, int64, error) {
	return c.ch.GetItems(offset, limit, "desc")
}

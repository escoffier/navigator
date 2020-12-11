package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	scannedImagesKey           = "ScannedImages"
	ScannedImagesCountCacheKey = "ScannedImagesCount"
)

type ScannedImagesCache struct {
	ctx          context.Context
	redisClient  *redis.Client
	mongodb      *mongo.Database
	ch           *util.CacheHelper
	harborClient *harbor.HarborRESTClient
}

func NewScannedImagesCache(
	ctx context.Context,
	mongodb *mongo.Database,
	redisClient *redis.Client,
	harborClient *harbor.HarborRESTClient,
) *ScannedImagesCache {

	c := &ScannedImagesCache{
		ctx:          ctx,
		mongodb:      mongodb,
		redisClient:  redisClient,
		harborClient: harborClient,
	}
	c.ch = util.NewCacheHelper(
		ctx,
		"ScannedImages",
		redisClient,
		c.getScannedImagesMaxEntryTimestamp,
		util.FinishedAtKey,
	)

	for _, maxImageAgeInHours := range []int{0, 1, 24} {
		for _, mongoFieldSortBy := range model.ScannedImagesSortableFields {
			c.ch.AddToRegistry(
				c.getScannedImagesData(maxImageAgeInHours, mongoFieldSortBy),
				strconv.Itoa(maxImageAgeInHours), mongoFieldSortBy)
		}
	}

	return c
}

func (c *ScannedImagesCache) getScannedImagesMaxEntryTimestamp() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, util.MongoTimeout)
	defer cancel()
	filter := bson.M{
		"$and": []bson.M{
			{"stale": false},
			{"status": model.ScanStatusSucceeded},
		},
	}

	findOptions := options.FindOne()
	findOptions.SetSort(bson.D{{"finishedAt", -1}})

	coll := c.mongodb.Collection(model.ScanTasksCollection.String())
	singleResult := coll.FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return -1, nil
		}
		return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
	}

	var scanTask model.ScanTask
	err := singleResult.Decode(&scanTask)
	if err != nil {
		return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
	}
	return scanTask.FinishedAt, nil
}

func (c *ScannedImagesCache) getScannedImagesData(
	maxImageAgeInHours int, sortBy string) func() ([]model.CacheEntry, error) {
	return func() ([]model.CacheEntry, error) {
		filter := bson.M{
			"$and": []bson.M{
				{"stale": false},
				{"status": model.ScanStatusSucceeded},
			},
		}
		if maxImageAgeInHours != 0 {
			imageTimeFilter := time.Now().Add(
				time.Duration(-1*maxImageAgeInHours) * time.Hour)
			filter = bson.M{
				"$and": []bson.M{
					{"stale": false},
					{"status": model.ScanStatusSucceeded},
					{"firstScanAt": bson.M{"$gt": imageTimeFilter.Unix()}},
				},
			}
		}
		findOptions := options.FindOptions{}
		findOptions.SetSort(bson.D{{sortBy, util.SortOrderToInt("asc")}})

		coll := c.mongodb.Collection(model.ScanTasksCollection.String())
		scannedImagesIds, err := dataToIds(
			c.ctx, filter, &findOptions, coll)
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Could not get ids to cache: %w", err))
		}

		harborCtx, harborCtxCancel := context.WithTimeout(c.ctx, time.Second*10)
		defer harborCtxCancel()

		status, err := c.harborClient.GetScanAllStatus(harborCtx)
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to get harbor scan status: %w", err))
		}

		redisCtx, redisCtxCancel := context.WithTimeout(c.ctx, util.RedisTimeout)
		defer redisCtxCancel()

		statusBytes, err := json.Marshal(status)
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to marshal harbor response: %w", err))
		}
		err = c.redisClient.Set(redisCtx, ScannedImagesCountCacheKey, statusBytes, 0).Err()
		if err != nil {
			return nil, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Set redis maxEntryTimestamp error: %w", err))
		}

		return scannedImagesIds, nil
	}
}

func (c *ScannedImagesCache) GetItems(
	ctx context.Context, maxImageAgeInHours int, offset int64, limit int64, sortBy string, sortOrder string) ([]model.CacheEntry, int64, error) {
	return c.ch.GetItems(offset, limit, sortOrder, strconv.Itoa(maxImageAgeInHours), sortBy)
}

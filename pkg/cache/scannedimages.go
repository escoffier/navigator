package cache

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	scannedImagesKey = "ScannedImages"
)

type ScannedImagesCache struct {
	ctx     context.Context
	mongodb *mongo.Database
	ch      *util.CacheHelper
}

func NewScannedImagesCache(
	ctx context.Context,
	mongodb *mongo.Database,
	redisClient *redis.Client,
) *ScannedImagesCache {

	c := &ScannedImagesCache{
		ctx:     ctx,
		mongodb: mongodb,
	}
	c.ch = util.NewCacheHelper(
		ctx,
		"ScannedImages",
		redisClient,
		c.getScannedImagesMaxEntryTimestamp,
		util.FinishedAtKey,
		true,
	)

	for _, maxImageAgeInHours := range []int{0, 1, 24} {
		for _, sortBy := range model.GetScannedImagesSortableNames() {
			c.ch.AddToRegistry(c.getScannedImagesData(maxImageAgeInHours, model.GetScannedImagesSortableField(sortBy)), strconv.Itoa(maxImageAgeInHours), model.GetScannedImagesSortableField(sortBy))
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

	singleResult := c.mongodb.Collection(model.ScanTasksCollection.String()).FindOne(ctx, filter, findOptions)
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

func (c *ScannedImagesCache) getScannedImagesData(maxImageAgeInHours int, sortBy string) func() ([]model.CacheEntry, error) {
	return func() ([]model.CacheEntry, error) {
		filter := bson.M{
			"$and": []bson.M{
				{"stale": false},
				{"status": model.ScanStatusSucceeded},
			},
		}
		if maxImageAgeInHours != 0 {
			imageTimeFilter := time.Now().Add(time.Duration(-1*maxImageAgeInHours) * time.Hour)
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

		scannedImagesIds, err := dataToIds(c.ctx, filter, &findOptions, c.mongodb.Collection(model.ScanTasksCollection.String()))
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Could not get ids to cache: %w", err))
		}
		return scannedImagesIds, nil
	}
}

func (c *ScannedImagesCache) GetItems(ctx context.Context, maxImageAgeInHours int, offset int64, limit int64, sortBy string, sortOrder string) ([]model.CacheEntry, int64, error) {
	err := c.ch.CheckVersionAndSyncData()
	if err != nil {
		return nil, 0, err
	}
	return c.ch.GetItems(offset, limit, sortOrder, strconv.Itoa(maxImageAgeInHours), sortBy)
}

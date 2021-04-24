package cache

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	imageVulnerabilitiesKey = "ImageVulnerabilities"
)

type ImageVulnerabilityCache struct {
	ctx     context.Context
	mongodb *mongotools.DatabaseWrapper
	ch      *util.CacheHelper
}

func NewImageVulnerabilityCache(
	ctx context.Context,
	mongodb *mongotools.DatabaseWrapper,
	redisClient *redis.Client,
) *ImageVulnerabilityCache {

	c := &ImageVulnerabilityCache{
		ctx:     ctx,
		mongodb: mongodb,
	}
	c.ch = util.NewCacheHelper(
		ctx,
		"ImageVulnerabilities",
		redisClient,
		c.getVulnerabilityInImagesMaxEntryTimestamp,
		util.CreatedAtKey,
	)

	for riskFilter, riskFilterVal := range model.VulnerabilityInImagesRiskFilters {
		c.ch.AddToRegistry(c.getVulnerabilityInImagesData(riskFilterVal), riskFilter)
	}

	return c
}

func (c *ImageVulnerabilityCache) getVulnerabilityInImagesMaxEntryTimestamp() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 1*time.Second)
	defer cancel()
	filter := bson.M{
		"$and": []bson.M{
			{"stale": false},
			{"status": model.ScanStatusSucceeded},
		},
	}

	findOptions := options.FindOne().SetMaxTime(500 * time.Millisecond)
	findOptions.SetSort(bson.D{{"finishedAt", -1}})

	coll := c.mongodb.Get().Collection(model.ScanTasksCollection.String())
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

func (c *ImageVulnerabilityCache) getVulnerabilityInImagesData(riskFilterInt int) func() ([]model.CacheEntry, error) {
	return func() ([]model.CacheEntry, error) {
		filter := bson.M{
			"$and": []bson.M{
				{"scanType": bson.M{"$gte": riskFilterInt}},
				{"historicised_timestamp": bson.M{"$exists": false}},
			},
		}

		mongoCtx, mongoCtxCancel := context.WithTimeout(c.ctx, 10*time.Second)
		defer mongoCtxCancel()

		findOptions := &options.FindOptions{}
		findOptions.SetMaxTime(3 * time.Second)

		coll := c.mongodb.Get().Collection(model.VulnerabilitiesInImagesCollection.String())

		cursor, err := coll.Find(mongoCtx, filter, findOptions)
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find documents: %w ", err))
		}
		defer cursor.Close(mongoCtx)

		vulnerabilitiesInImagesIds := make([]model.CacheEntry, 0)
		vulnerabilitiesInImages := make([]model.VulnerabilityInImages, 0)
		for cursor.Next(mongoCtx) {
			var vulnerabilityInImages model.VulnerabilityInImages
			err := cursor.Decode(&vulnerabilityInImages)
			if err != nil {
				return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document error: %w ", err))
			}
			vulnerabilitiesInImages = append(vulnerabilitiesInImages, vulnerabilityInImages)
		}
		err = cursor.Err()
		if err != nil {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("mongo cursor error: %w", err))
		}
		redclair.SortVulnerabilitiesInImagesBySeverityAndStuff(vulnerabilitiesInImages, true)
		for _, v := range vulnerabilitiesInImages {
			vulnerabilitiesInImagesIds = append(vulnerabilitiesInImagesIds, model.CacheEntry{
				ID: v.ID,
			})
		}
		return vulnerabilitiesInImagesIds, nil
	}
}

func (c *ImageVulnerabilityCache) GetItems(ctx context.Context, riskFilter string, offset int64, limit int64, sortOrder string) ([]model.CacheEntry, int64, error) {
	return c.ch.GetItems(offset, limit, sortOrder, riskFilter)
}

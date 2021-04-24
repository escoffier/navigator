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
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	rulesKey = "Rules"
)

type RulesCache struct {
	ctx     context.Context
	mongodb *mongotools.DatabaseWrapper
	ch      *util.CacheHelper
}

func NewRulesCache(
	ctx context.Context,
	mongodb *mongotools.DatabaseWrapper,
	redisClient *redis.Client,
) *RulesCache {

	c := &RulesCache{
		ctx:     ctx,
		mongodb: mongodb,
	}
	c.ch = util.NewCacheHelper(
		ctx,
		"Rules",
		redisClient,
		c.getRulesMaxEntryTimestamp,
		util.CreatedAtKey,
	)
	c.ch.AddToRegistry(c.getRulesData)
	return c
}

func (c *RulesCache) getRulesMaxEntryTimestamp() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	filter := bson.M{}

	findOptions := options.FindOne().SetMaxTime(500 * time.Millisecond)
	findOptions.SetSort(bson.D{{"created_at", -1}})

	singleResult := c.mongodb.Get().Collection(model.RulesCollection.String()).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return -1, nil
		}
		return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
	}

	var rule model.Rule
	err := singleResult.Decode(&rule)
	if err != nil {
		return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
	}

	createdAt := rule.CreatedAt.Unix()

	findOptions = options.FindOne().SetMaxTime(500 * time.Millisecond)
	findOptions.SetSort(bson.D{{"created_at", -1}})

	singleResult = c.mongodb.Get().Collection(model.RulesCollection.String()).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return -1, nil
		}
		return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
	}

	err = singleResult.Decode(&rule)
	if err != nil {
		return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
	}

	deletedAt := rule.DeletedAt.Unix()

	if createdAt > deletedAt {
		return createdAt, nil
	}
	return deletedAt, nil
}

func (c *RulesCache) getRulesData() ([]model.CacheEntry, error) {
	filter := bson.M{"deleted_at": bson.M{"$exists": false}}
	findOptions := options.FindOptions{}
	findOptions.SetSort(bson.D{{"created_at", -1}})

	rulesIds, err := dataToIds(c.ctx, filter, &findOptions, c.mongodb.Get().Collection(model.RulesCollection.String()))
	if err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Could not get ids to cache: %w", err))
	}
	return rulesIds, nil
}

func (c *RulesCache) GetItems(ctx context.Context, offset int64, limit int64) ([]model.CacheEntry, int64, error) {
	return c.ch.GetItems(offset, limit, "desc")
}

func (c *RulesCache) RefreshCache() error {
	err := c.ch.CheckVersionAndSyncData()
	return err
}

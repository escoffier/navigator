package cache

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-redis/redis/v8"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	scapKey                = "Scap"
	clusterRefreshInterval = time.Second * 30
)

type ScapCache struct {
	ctx     context.Context
	mongodb *mongotools.DatabaseWrapper
	ch      *CacheHelper
}

func NewScapCache(
	ctx context.Context,
	mongodb *mongotools.DatabaseWrapper,
	redisClient *redis.Client,
	checkType model.ComplianceCheckType,
) (*ScapCache, error) {

	c := &ScapCache{
		ctx:     ctx,
		mongodb: mongodb,
	}
	c.ch = NewCacheHelper(
		ctx,
		"Scap",
		redisClient,
		c.getScapMaxEntryTimestamp(checkType),
		FinishedAtKey,
	)

	for _, checkType := range []model.ComplianceCheckType{model.ComplianceCheckTargetTypeDocker, model.ComplianceCheckTargetTypeHost, model.ComplianceCheckTargetTypeKube} {
		for _, sortBy := range model.GetScapSortableNames() {
			c.ch.AddToRegistry(c.getScapData(checkType, "", sortBy), string(checkType), "", sortBy)
		}
	}

	go c.refreshClusterCacheKeys(ctx, checkType)

	return c, nil
}

func (c *ScapCache) doRefreshClusterCacheKeys(ctx context.Context, checkType model.ComplianceCheckType) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	clusterFilter := bson.M{}
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, 1*time.Second)
	defer mongoCtxCancel()

	clusterFindOptions := options.FindOptions{}
	clusterFindOptions.SetSort(bson.D{{"createdAt", -1}})
	clusterFindOptions.SetMaxTime(1 * time.Second)
	clusterCursor, err := c.mongodb.Get().Collection(model.ClusterCollection.String()).Find(mongoCtx, clusterFilter, &clusterFindOptions)
	if err != nil {
		logging.GetLogger().Error().Str("checkType", string(checkType)).Err(NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't find documents: %w ", err)))
		return
	}
	defer clusterCursor.Close(mongoCtx)
	for _, checkType := range []model.ComplianceCheckType{model.ComplianceCheckTargetTypeDocker, model.ComplianceCheckTargetTypeHost, model.ComplianceCheckTargetTypeKube} {
		for _, sortBy := range model.GetScapSortableNames() {
			mongoSortableField := model.GetScapSortableField(sortBy)
			for clusterCursor.Next(mongoCtx) {
				var cluster model.Cluster
				err := clusterCursor.Decode(&cluster)
				if err != nil {
					logging.GetLogger().Error().Str("checkType", string(checkType)).Err(NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document error: %w ", err)))
					continue
				}
				if cluster.DeletedAt.IsZero() {
					if !c.ch.ExistsInRegistry(string(checkType), cluster.ID.Hex(), mongoSortableField) {
						fmt.Println(string(checkType), cluster.ID.Hex(), mongoSortableField)
						c.ch.AddToRegistry(c.getScapData(checkType, cluster.ID.Hex(), mongoSortableField), string(checkType), cluster.ID.Hex(), mongoSortableField)
					}
				} else {
					if c.ch.ExistsInRegistry(string(checkType), cluster.ID.Hex(), mongoSortableField) {
						fmt.Println(string(checkType), cluster.ID.Hex(), mongoSortableField)
						c.ch.RemoveFromRegistry(string(checkType), cluster.ID.Hex(), mongoSortableField)
					}
				}
			}
			err = clusterCursor.Err()
			if err != nil {
				logging.GetLogger().Error().Str("checkType", string(checkType)).Err(NewAnError(http.StatusInternalServerError, fmt.Errorf("mongo cursor error: %w", err)))
			}
		}
	}
}
func (c *ScapCache) refreshClusterCacheKeys(ctx context.Context, checkType model.ComplianceCheckType) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	ticker := time.NewTicker(clusterRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.doRefreshClusterCacheKeys(ctx, checkType)
		}
	}
}

func (c *ScapCache) getScapMaxEntryTimestamp(checkType model.ComplianceCheckType) func() (int64, error) {
	return func() (int64, error) {
		ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
		defer cancel()
		filter := bson.M{"checkType": string(checkType)}

		findOptions := options.FindOne().SetMaxTime(500 * time.Millisecond)
		findOptions.SetSort(bson.D{{"finishedAt", -1}})

		singleResult := c.mongodb.Get().Collection(model.CheckHistoryEntryCollection.String()).FindOne(ctx, filter, findOptions)
		if singleResult.Err() != nil {
			if singleResult.Err() == mongo.ErrNoDocuments {
				return -1, nil
			}
			return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
		}

		var scapJob model.ComplianceCheckEntryBase
		err := singleResult.Decode(&scapJob)
		if err != nil {
			return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
		}
		finishedAt := scapJob.FinishedAt

		findOptions = options.FindOne().SetMaxTime(500 * time.Millisecond)
		findOptions.SetSort(bson.D{{"createdAt", -1}})

		singleResult = c.mongodb.Get().Collection(model.CheckHistoryEntryCollection.String()).FindOne(ctx, filter, findOptions)
		if singleResult.Err() != nil {
			if singleResult.Err() == mongo.ErrNoDocuments {
				return -1, nil
			}
			return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
		}

		err = singleResult.Decode(&scapJob)
		if err != nil {
			return -1, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
		}

		createdAt := scapJob.FinishedAt
		if finishedAt > createdAt {
			return finishedAt, nil
		}
		return createdAt, nil
	}
}

func (c *ScapCache) getScapData(checkType model.ComplianceCheckType, clusterID string, sortBy string) func() ([]model.CacheEntry, error) {
	return func() ([]model.CacheEntry, error) {
		filter := bson.M{"checkType": checkType}
		if clusterID != "" {
			filter["clusterId"] = clusterID
		}

		findOptions := options.Find().SetSort(bson.D{{sortBy, util.SortOrderToInt("asc")}}).SetMaxTime(5 * time.Second)

		scapIds, err := dataToIds(c.ctx, filter, findOptions, c.mongodb.Get().Collection(model.CheckHistoryEntryCollection.String()))
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Could not get ids to cache: %w", err))
		}
		return scapIds, nil
	}
}

func (c *ScapCache) GetItems(ctx context.Context, checkType string, clusterID string, offset int64, limit int64, sortBy string, sortOrder string) ([]model.CacheEntry, int64, error) {
	return c.ch.GetItems(offset, limit, sortOrder, string(checkType), clusterID, sortBy)
}

func (c *ScapCache) RefreshCache() error {
	err := c.ch.CheckVersionAndSyncData()
	return err
}

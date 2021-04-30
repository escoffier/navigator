package cleanup

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"strings"
	"time"
)

type MongoCleaner struct {
	mongodb *mongotools.DatabaseWrapper
}

func NewMongoCleaner(mongodb *mongotools.DatabaseWrapper) *MongoCleaner {
	return &MongoCleaner{mongodb: mongodb}
}

func (c *MongoCleaner) Clean(ctx context.Context, daysOffset int) error {
	logging.GetLogger().Info().Msgf("mongo cleaner start, daysOffset:%d", daysOffset)
	fromTime := time.Now().Add(-time.Hour * time.Duration(daysOffset) * 24)
	var collectionInfos []bson.D
	allCollectionsCursor, err := c.mongodb.Get().ListCollections(ctx, bson.M{})
	if err != nil {
		return fmt.Errorf("couldn't list monogo collections: %w", err)
	}

	err = allCollectionsCursor.All(ctx, &collectionInfos)
	if err != nil {
		return fmt.Errorf("decode allCollectionsCursor fail: %w", err)
	}

	for _, collectionInfo := range collectionInfos {
		col, ok := collectionInfo.Map()["name"]
		if !ok {
			continue
		}

		colName, ok := col.(string)
		if !ok || colName == "" {
			continue
		}

		if strings.HasPrefix(colName, "system.") {
			continue
		}

		cleanFunc := func() error {
			return c.cleanCollection(ctx, colName, fromTime)
		}

		err = util.WithRetry(cleanFunc, util.DefaultRetryConf)
		if err != nil {
			return fmt.Errorf("cleanCollection fail:%w", err)
		}
	}

	logging.GetLogger().Info().Msg("mongo cleaner finished successfully")
	return nil
}

const (
	mongoBatch         = 1000
	mongoCleanInterval = time.Millisecond * 400
)

func (c *MongoCleaner) cleanCollection(ctx context.Context, colName string, fromTime time.Time) error {
	logging.GetLogger().Info().Msgf("start to clean collection:%s", colName)
	filter := bson.M{"historicised_timestamp": bson.M{"$lt": fromTime}}
	findOptions := &options.FindOptions{}
	cursor, err := c.mongodb.Get().Collection(colName).Find(ctx, filter,
		findOptions.
			SetNoCursorTimeout(true).
			SetBatchSize(mongoBatch).
			SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return fmt.Errorf("find collection fail:%w", err)
	}

	var record struct {
		ID primitive.ObjectID `bson:"_id"`
	}

	defer cursor.Close(ctx)
	var toBeDeleted = make([]primitive.ObjectID, 0, mongoBatch)
	var totalCount int
	for cursor.Next(ctx) {
		err = cursor.Decode(&record)
		if err != nil {
			return fmt.Errorf("decode record fail:%w", err)
		}

		totalCount++
		toBeDeleted = append(toBeDeleted, record.ID)
		if len(toBeDeleted) == mongoBatch {
			err = c.clearDataByID(ctx, colName, toBeDeleted)
			if err != nil {
				return fmt.Errorf("clearDataByID fail:%w", err)
			}
			toBeDeleted = toBeDeleted[:0]
			time.Sleep(mongoCleanInterval)
		}
	}

	if len(toBeDeleted) > 0 {
		err = c.clearDataByID(ctx, colName, toBeDeleted)
		if err != nil {
			return fmt.Errorf("clearDataByID fail:%w", err)
		}
	}

	logging.GetLogger().Info().
		Int("deletedCount", totalCount).
		Str("fromTime", fromTime.String()).
		Str("collection", colName).
		Msg("Removed audit documents older than")

	logging.GetLogger().Info().Msgf("clean collection successfully, collection:%s", colName)
	return nil
}

func (c *MongoCleaner) clearDataByID(ctx context.Context, colName string, toBeDeleted []primitive.ObjectID) error {
	deleteFilter := bson.M{"_id": bson.M{"$in": toBeDeleted}}
	_, err := c.mongodb.Get().Collection(colName).DeleteMany(ctx, deleteFilter)
	if err != nil {
		logging.GetLogger().Error().Msgf("delete documents fail, colName:%s, err:%s", colName, err.Error())
		return fmt.Errorf("cannot delete mongo documents, collection:%s, err:%w", colName, err)
	}

	return nil
}

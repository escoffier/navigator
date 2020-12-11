package cache

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	alertsKey = "Alerts"
)

type AlertsCache struct {
	ctx     context.Context
	mongodb *mongo.Database
	ch      *util.CacheHelper
}

func NewAlertsCache(
	ctx context.Context,
	mongodb *mongo.Database,
	redisClient *redis.Client,
) *AlertsCache {
	c := &AlertsCache{
		ctx:     ctx,
		mongodb: mongodb,
	}
	c.ch = util.NewCacheHelper(
		ctx,
		"Alerts",
		redisClient,
		c.getAlertsNewestEntryTimestamp,
		util.TimestampKey,
	)

	for _, onlyNotAcknowledged := range []bool{true, false} {
		for _, kind := range []model.AlertKind{model.AlertKindAny, model.AlertKindComplianceCheck, model.AlertKindRuntimeDetection, model.AlertKindExploitRisk} {
			for _, sortBy := range model.GetAlertSortableNames() {
				c.ch.AddToRegistry(c.getAlertsData(onlyNotAcknowledged, kind, model.GetAlertSortableField(sortBy)), strconv.FormatBool(onlyNotAcknowledged), string(kind), model.GetAlertSortableField(sortBy))
			}
		}
	}

	return c
}

func (c *AlertsCache) getAlertsNewestEntryTimestamp() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, util.MongoTimeout)
	defer cancel()
	filter := bson.M{}

	findOptions := options.FindOne()
	findOptions.SetSort(bson.D{{"timestamp", -1}})

	singleResult := c.mongodb.Collection(model.AlertsCollection.String()).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return -1, nil
		}
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
	}

	var alert model.Alert
	err := singleResult.Decode(&alert)
	if err != nil {
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
	}

	createdAt := alert.Timestamp.Unix()

	findOptions = options.FindOne()
	findOptions.SetSort(bson.D{{"historicised_timestamp", -1}})

	singleResult = c.mongodb.Collection(model.AlertsCollection.String()).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return -1, nil
		}
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
	}

	err = singleResult.Decode(&alert)
	if err != nil {
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
	}
	acknowledgedAt := alert.HistoricisedTimestamp.Unix()
	if acknowledgedAt > createdAt {
		return acknowledgedAt, nil
	}
	return createdAt, nil
}

func (c *AlertsCache) getAlertsData(onlyNotAcknowledged bool, kind model.AlertKind, sortBy string) func() ([]model.CacheEntry, error) {
	return func() ([]model.CacheEntry, error) {
		var filter bson.M = bson.M{}
		if onlyNotAcknowledged {
			filter = bson.M{"acknowledged": false}
		}
		if kind != model.AlertKindAny {
			filter["kind"] = kind
		}
		findOptions := options.FindOptions{}

		findOptions.SetSort(bson.D{{sortBy, util.SortOrderToInt("asc")}})

		alertIds, err := dataToIds(c.ctx, filter, &findOptions, c.mongodb.Collection(model.AlertsCollection.String()))
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Could not get ids to cache: %w", err))
		}
		return alertIds, nil
	}
}

func (c *AlertsCache) GetItems(ctx context.Context, kind model.AlertKind, offset int64, limit int64, sortBy string, sortOrder string, onlyNotAcknowledged bool) ([]model.CacheEntry, int64, error) {
	return c.ch.GetItems(offset, limit, sortOrder, strconv.FormatBool(onlyNotAcknowledged), string(kind), sortBy)
}

func (c *AlertsCache) RefreshCache() error {
	err := c.ch.CheckVersionAndSyncData()
	return err
}

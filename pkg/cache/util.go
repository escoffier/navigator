package cache

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func dataToIds(ctx context.Context, filter bson.M, findOptions *options.FindOptions, coll *mongo.Collection) ([]model.CacheEntry, error) {
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, util.MongoTimeout)
	defer mongoCtxCancel()

	mt := time.Second * 60
	findOptions.SetMaxTime(mt)
	findOptions.SetProjection(bson.M{"_id": 1})

	docNum, err := coll.CountDocuments(mongoCtx, filter)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document count: %w ", err))
	}

	cursor, err := coll.Find(mongoCtx, filter, findOptions)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find documents: %w ", err))
	}
	defer cursor.Close(ctx)

	idsList := make([]model.CacheEntry, docNum)
	var i = 0
	for cursor.Next(ctx) {
		var cacheEntry model.CacheEntry
		err := cursor.Decode(&cacheEntry)
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document error: %w ", err))
		}
		idsList[i] = cacheEntry
		i = i + 1
		if int64(i) == docNum {
			break
		}
	}
	err = cursor.Err()
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("mongo cursor error: %w", err))
	}
	return idsList, nil
}

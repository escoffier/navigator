package ttlmanager

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Manager struct {
	mongodb    *mongotools.DatabaseWrapper
	collection string
}

func NewManager(mongodb *mongotools.DatabaseWrapper, collection string) *Manager {
	return &Manager{
		mongodb:    mongodb,
		collection: collection,
	}
}

func (m *Manager) GetTTLDayOffset(ctx context.Context, taskType def.GCTaskType) (int, error) {
	if !taskType.Check() {
		return 0, def.ErrInvalidDataType
	}

	filter := bson.M{
		"category": taskType.String(),
	}

	result := m.mongodb.Get().Collection(m.collection).FindOne(ctx, filter)
	if result.Err() != nil {
		if result.Err() != mongo.ErrNoDocuments {
			return 0, result.Err()
		}
		return def.DefaultTTLDays[taskType], nil
	}

	var record model.DataTTLRecord
	err := result.Decode(&record)
	if err != nil {
		return 0, err
	}

	return record.TTL, nil
}

func (m *Manager) SetTTLDayOffset(ctx context.Context, taskType def.GCTaskType, dayOffsetTTL int) error {
	opts := options.Update().SetUpsert(true)
	filter := bson.M{"category": taskType.String()}
	update := bson.D{{Key: "$set",
		Value: bson.D{{Key: "ttl", Value: dayOffsetTTL},
			{Key: "updated_at", Value: time.Now()}},
	}}

	result, err := m.mongodb.Get().Collection(m.collection).UpdateOne(ctx, filter, update, opts)
	if err != nil {
		logging.GetLogger().Error().Msgf("SetTTLDayOffset fail, err:%s", err.Error())
		return err
	}

	logging.GetLogger().Info().Msgf("SetTTLDayOffset successfully, result:%+v", result)
	return nil
}

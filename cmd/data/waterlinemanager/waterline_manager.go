package waterlinemanager

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

func (m *Manager) GetWaterline(ctx context.Context) (int, error) {
	result := m.mongodb.Get().Collection(m.collection).FindOne(ctx, bson.M{})
	if result.Err() != nil {
		if result.Err() != mongo.ErrNoDocuments {
			return 0, result.Err()
		}
		return def.DefaultWaterlinePercentage, nil
	}

	var record model.WaterlineRecord
	err := result.Decode(&record)
	if err != nil {
		return 0, err
	}

	return record.Percentage, nil
}

func (m *Manager) SetWaterline(ctx context.Context, percentage int) error {
	opts := options.Update().SetUpsert(true)
	update := bson.D{{Key: "$set",
		Value: bson.D{{Key: "percentage", Value: percentage},
			{Key: "updated_at", Value: time.Now()}},
	}}

	result, err := m.mongodb.Get().Collection(m.collection).UpdateOne(ctx, bson.M{}, update, opts)
	if err != nil {
		logging.GetLogger().Error().Msgf("SetWaterline fail, err:%s", err.Error())
		return err
	}

	logging.GetLogger().Info().Msgf("SetWaterline successfully, result:%+v", result)
	return nil
}

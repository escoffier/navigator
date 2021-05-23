package taskmanager

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Manager struct {
	mongodb      *mongotools.DatabaseWrapper
	collection   string
	maxCleanTime time.Duration
}

func NewManager(mongodb *mongotools.DatabaseWrapper, collection string, maxCleanTime time.Duration) *Manager {
	return &Manager{
		mongodb:      mongodb,
		collection:   collection,
		maxCleanTime: maxCleanTime,
	}
}

func (m *Manager) CreateGCTask(ctx context.Context, taskType def.GCTaskType) (*model.GCTask, error) {
	if !taskType.Check() {
		return nil, def.ErrUnknownTaskType
	}

	nowTime := time.Now()
	newGCTask := &model.GCTask{
		ID:        primitive.NewObjectIDFromTimestamp(nowTime),
		Category:  taskType.String(),
		Status:    model.GCInProgress,
		StartTime: nowTime,
	}

	collection := m.mongodb.Get().Collection(m.collection)

	filter := bson.M{"status": model.GCInProgress, "category": taskType.String()}

	err := m.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return fmt.Errorf("couldn't start transaction: %w", sessionError)
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		queryResult := collection.FindOne(sessionContext, filter)

		if queryResult.Err() == nil {
			sessionError = fmt.Errorf("GC in progress")
			return def.ErrTaskConflict
		}

		if queryResult.Err() != mongo.ErrNoDocuments {
			sessionError = queryResult.Err()
			return fmt.Errorf("mongo error:%w", queryResult.Err())
		}

		_, sessionError = collection.InsertOne(sessionContext, newGCTask)
		if sessionError != nil {
			return fmt.Errorf("couldn't insert document: %w", sessionError)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return newGCTask, nil
}

func (m *Manager) GetGCTask(ctx context.Context, taskID primitive.ObjectID) (*model.GCTask, error) {
	filter := bson.M{"_id": taskID}
	queryResult := m.mongodb.Get().Collection(m.collection).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, def.ErrTaskNotFound
		}
		return nil, fmt.Errorf("couldn't get document: %w", queryResult.Err())
	}
	var queryGCTask model.GCTask
	err := queryResult.Decode(&queryGCTask)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode document: %w", queryResult.Err())
	}
	return &queryGCTask, nil
}

func (m *Manager) UpdateTaskStatus(ctx context.Context, taskID primitive.ObjectID, status string) error {
	retryFunc := func() error {
		gcTask, err := m.GetGCTask(ctx, taskID)
		if err != nil {
			return fmt.Errorf("could not get GC Task: %w", err)
		}
		gcTask.HistoricisedTimestamp = time.Now()
		gcTask.Status = status
		update := bson.M{"$set": gcTask}
		filter := bson.M{"_id": gcTask.ID}

		_, err = m.mongodb.Get().Collection(m.collection).UpdateOne(ctx, filter, update)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return fmt.Errorf("document not found: %w", err)
			}

			return fmt.Errorf("couldn't remove document: %w", err)
		}
		return nil
	}

	return util.WithRetry(retryFunc, util.DefaultRetryConf)
}

func (m *Manager) DealExpireTasks(ctx context.Context, nowTime time.Time) error {
	filter := bson.M{
		"$and": []bson.M{
			{"startTime": bson.M{"$lt": nowTime.Add(-m.maxCleanTime)}},
			{"status": model.GCInProgress},
		},
	}
	update := bson.M{"$set": bson.M{"status": model.GCFailed}}
	updateResult, err := m.mongodb.Get().Collection(m.collection).UpdateMany(ctx, filter, update)
	if err != nil {
		logging.GetLogger().Error().Msgf("dealExpiredGCTasks fail, err:%s", err.Error())
	} else {
		logging.GetLogger().Info().Msgf("dealExpiredGCTasks, updateResult:%+v", updateResult)
	}

	return nil
}

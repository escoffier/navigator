package cleanup

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"
)

type Service struct {
	mongodb *mongotools.DatabaseWrapper

	mongoPod   *PodInfo
	esPod      *PodInfo
	postgrePod *PodInfo

	logicCleaners   []Cleaner
	offlineCleaners []Cleaner

	kubeClient atomic.Value
	restConfig atomic.Value
}

type PodInfo struct {
	PVC      string
	Pod      string
	DataPath string
}

type Conf struct {
	Mongodb     *mongotools.DatabaseWrapper
	MongoPod    *PodInfo
	ElasticOpts *flag.ElasticOpts
	ESPod       *PodInfo
	PostgreDB   *rdbtools.GormWrapper
	PostgrePod  *PodInfo
}

func NewCleanupService(conf *Conf) *Service {
	service := &Service{
		mongodb:    conf.Mongodb,
		mongoPod:   conf.MongoPod,
		esPod:      conf.ESPod,
		postgrePod: conf.PostgrePod,
		logicCleaners: []Cleaner{
			NewMongoCleaner(conf.Mongodb),
			NewPostgresCleaner(conf.PostgreDB),
		},
		offlineCleaners: []Cleaner{
			NewESCleaner(conf.ElasticOpts),
		},
	}

	var kubeClient *kubernetes.Clientset
	var restConfig *rest.Config
	service.kubeClient.Store(kubeClient)
	service.restConfig.Store(restConfig)

	go service.asyncLoop()
	return service
}

type Cleaner interface {
	Clean(ctx context.Context, daysOffset int) error
}

const (
	GCTaskTypeLogic   = 1
	GCTaskTypeOffline = 2
)

var (
	gcType2Collection = map[int]string{
		GCTaskTypeLogic:   model.GCCollection.String(),
		GCTaskTypeOffline: model.ESGCCollection.String(),
	}

	ErrUnknownTaskType = fmt.Errorf("unknown gc task type")
)

func (s *Service) CreateGCTask(ctx context.Context, taskType int) (*model.GCTask, error) {
	colName, ok := gcType2Collection[taskType]
	if !ok {
		return nil, ErrUnknownTaskType
	}

	nowTime := time.Now()
	newGCTask := &model.GCTask{
		ID:        primitive.NewObjectIDFromTimestamp(nowTime),
		Status:    model.GCInProgress,
		StartTime: nowTime,
	}

	collection := s.mongodb.Get().Collection(colName)

	filter := bson.M{"status": model.GCInProgress}

	err := s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		queryResult := collection.FindOne(sessionContext, filter)

		if queryResult.Err() == nil {
			sessionError = fmt.Errorf("GC in progress")
			return apperror.NewGarbageCollectionInProgressError(http.StatusConflict, sessionError)
		}

		if queryResult.Err() != mongo.ErrNoDocuments {
			return apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("mongo error:%w", queryResult.Err()))
		}

		_, sessionError = collection.InsertOne(sessionContext, newGCTask)
		if sessionError != nil {
			return apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't insert document: %w", sessionError))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return newGCTask, nil
}

func (s *Service) GetGCTask(ctx context.Context, gcTaskID primitive.ObjectID, taskType int) (*model.GCTask, error) {
	colName, ok := gcType2Collection[taskType]
	if !ok {
		return nil, ErrUnknownTaskType
	}

	filter := bson.M{"_id": gcTaskID}
	queryResult := s.mongodb.Get().Collection(colName).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, apperror.NewMongoError(http.StatusNotFound, fmt.Errorf("task not found"))
		}
		return nil, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't get document: %w", queryResult.Err()))
	}
	var queryGCTask model.GCTask
	err := queryResult.Decode(&queryGCTask)
	if err != nil {
		return nil, apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("couldn't decode document: %w", queryResult.Err()))
	}
	return &queryGCTask, nil
}

func (s *Service) RunLogicGarbageCollection(ctx context.Context, daysOffset int, gcTaskID primitive.ObjectID) {
	s.runGarbageCollection(ctx, daysOffset, gcTaskID, GCTaskTypeLogic)
}

func (s *Service) RunOfflineGarbageCollection(ctx context.Context, daysOffset int, gcTaskID primitive.ObjectID) {
	s.runGarbageCollection(ctx, daysOffset, gcTaskID, GCTaskTypeOffline)
}

const (
	MaxCleanTime = time.Hour * 24
)

func (s *Service) getCleaners(gcType int) []Cleaner {
	var gcType2Cleaners = map[int][]Cleaner{
		GCTaskTypeLogic:   s.logicCleaners,
		GCTaskTypeOffline: s.offlineCleaners,
	}

	return gcType2Cleaners[gcType]
}

func (s *Service) runGarbageCollection(ctx context.Context, daysOffset int, gcTaskID primitive.ObjectID, gcType int) {
	gcCtx, cancel := context.WithTimeout(ctx, MaxCleanTime)
	defer cancel()
	var group errgroup.Group
	cleaners := s.getCleaners(gcType)
	for _, cleaner := range cleaners {
		cleaner := cleaner
		group.Go(func() error {
			return cleaner.Clean(gcCtx, daysOffset)
		})
	}

	err := group.Wait()
	if err != nil {
		logging.GetLogger().Error().Msgf("RunLogicGarbageCollection fail, err:%s", err.Error())
		err = s.updateGCStatus(gcCtx, gcTaskID, gcType, model.GCFailed)
		if err != nil {
			logging.GetLogger().Error().Err(fmt.Errorf("failed to update GC status: %w", err))
		}
		return
	}

	logging.GetLogger().Info().Str("gcTaskId", gcTaskID.Hex()).Msg("GC Task finished successfully")
	err = s.updateGCStatus(gcCtx, gcTaskID, gcType, model.GCCompleted)
	if err != nil {
		logging.GetLogger().Error().Err(fmt.Errorf("failed to update GC status: %w", err))
	}
}

func (s *Service) updateGCStatus(ctx context.Context, gcTaskID primitive.ObjectID, taskType int, gcStatus string) error {
	retryFunc := func() error {
		gcTask, err := s.GetGCTask(ctx, gcTaskID, taskType)
		if err != nil {
			return fmt.Errorf("could not get GC Task: %w", err)
		}
		gcTask.HistoricisedTimestamp = time.Now()
		gcTask.Status = gcStatus
		update := bson.M{"$set": gcTask}
		filter := bson.M{"_id": gcTask.ID}

		_, err = s.mongodb.Get().Collection(gcType2Collection[taskType]).UpdateOne(ctx, filter, update)
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

const (
	checkInterval = time.Hour
)

func (s *Service) asyncLoop() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when checking ttl: %v. stack: %s", r, debug.Stack())
		}
	}()

	// wait for service ready
	<-time.After(time.Second * 5)

	s.dealExpiredGCTasks(time.Now())
	ticker := time.NewTicker(checkInterval)
	for t := range ticker.C {
		s.dealExpiredGCTasks(t)
	}
}

func (s *Service) dealExpiredGCTasks(nowTime time.Time) {
	logging.GetLogger().Info().Msgf("dealExpiredGCTasks, time:%s", nowTime)

	ctx, cancel := context.WithTimeout(context.Background(), checkInterval)
	defer cancel()
	collections := []string{model.GCCollection.String(), model.ESGCCollection.String()}
	filter := bson.M{
		"$and": []bson.M{
			{"startTime": bson.M{"$lt": nowTime.Add(-MaxCleanTime)}},
			{"status": model.GCInProgress},
		},
	}
	update := bson.M{"$set": bson.M{"status": model.GCFailed}}
	for _, collection := range collections {
		updateResult, err := s.mongodb.Get().Collection(collection).UpdateMany(ctx, filter, update)
		if err != nil {
			logging.GetLogger().Error().Msgf("dealExpiredGCTasks fail, collection:%s, err:%s", collection, err.Error())
		} else {
			logging.GetLogger().Info().Msgf("dealExpiredGCTasks, collection:%s, updateResult:%+v", collection, updateResult)
		}
	}
}

package cleanup

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/rs/zerolog"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type CleanupService struct {
	mongodb       *mongotools.DatabaseWrapper
	mongoPVC      string
	mongoPod      string
	mongoDataPath string
	es            *elastic.Client
	elasticOpts   *flag.ElasticOpts
	esPVC         string
	esPod         string
	esDataPath    string
	kubeClient    *kubernetes.Clientset
	restConfig    *rest.Config
}

func NewCleanupService(
	mongodb *mongotools.DatabaseWrapper,
	mongoPVC string,
	mongoPod string,
	mongoDataPath string,
	es *elastic.Client,
	elasticOpts *flag.ElasticOpts,
	esPVC string,
	esPod string,
	esDataPath string,
) *CleanupService {
	return &CleanupService{
		mongodb:       mongodb,
		mongoPVC:      mongoPVC,
		mongoPod:      mongoPod,
		mongoDataPath: mongoDataPath,
		es:            es,
		elasticOpts:   elasticOpts,
		esPVC:         esPVC,
		esPod:         esPod,
		esDataPath:    esDataPath,
		kubeClient:    nil,
		restConfig:    nil,
	}
}

type Esquery struct {
	Query struct {
		Range struct {
			Timestamp struct {
				Lt     string `json:"lt"`
				Format string `json:"format"`
			} `json:"@timestamp"`
		} `json:"range"`
	} `json:"query"`
}

// OnKubeConfigUpdate should be called e.g. when cluster modified or added
// When cluster deleted, set kubeClient to nil.
func (s *CleanupService) OnKubeConfigUpdate(newClient *kubernetes.Clientset, restConfig *rest.Config) {
	s.kubeClient = newClient
	s.restConfig = restConfig
}

func (s *CleanupService) CreateGCTask(ctx context.Context) (*model.GCTask, error) {
	newGCTask := &model.GCTask{
		ID:     primitive.NewObjectIDFromTimestamp(time.Now()),
		Status: model.GCInProgress,
	}

	collection := s.mongodb.Get().Collection(model.GCCollection.String())

	filter := bson.M{"status": model.GCInProgress}

	err := s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		queryResult := collection.FindOne(sessionContext, filter)

		if queryResult.Err() == nil {
			sessionError = fmt.Errorf("GC in progress")
			return NewGarbageCollectionInProgressError(http.StatusConflict, sessionError)
		}

		_, sessionError = collection.InsertOne(sessionContext, newGCTask)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", sessionError))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return newGCTask, nil
}

func (s *CleanupService) CreateESGCTask(ctx context.Context) (*model.GCTask, error) {
	newGCTask := &model.GCTask{
		ID:     primitive.NewObjectIDFromTimestamp(time.Now()),
		Status: model.GCInProgress,
	}

	collection := s.mongodb.Get().Collection(model.ESGCCollection.String())

	filter := bson.M{"status": model.GCInProgress}

	err := s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		queryResult := collection.FindOne(sessionContext, filter)

		if queryResult.Err() == nil {
			sessionError = fmt.Errorf("GC in progress")
			return NewGarbageCollectionInProgressError(http.StatusConflict, sessionError)
		}

		_, sessionError = collection.InsertOne(sessionContext, newGCTask)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", sessionError))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return newGCTask, nil
}

func (s *CleanupService) GetGCTask(ctx context.Context, gcTaskID primitive.ObjectID) (*model.GCTask, error) {
	filter := bson.M{"_id": gcTaskID}

	queryResult := s.mongodb.Get().Collection(model.GCCollection.String()).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}
	var queryGCTask model.GCTask
	err := queryResult.Decode(&queryGCTask)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	return &queryGCTask, nil
}

func (s *CleanupService) GetESGCTask(ctx context.Context, gcTaskID primitive.ObjectID) (*model.GCTask, error) {
	filter := bson.M{"_id": gcTaskID}

	queryResult := s.mongodb.Get().Collection(model.ESGCCollection.String()).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}
	var queryGCTask model.GCTask
	err := queryResult.Decode(&queryGCTask)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	return &queryGCTask, nil
}

func (s *CleanupService) updateGCStatus(ctx context.Context, gcTask *model.GCTask, gcStatus string) error {
	gcTask, err := s.GetGCTask(ctx, gcTask.ID)
	if err != nil {
		return NewGarbageCollectionError(http.StatusInternalServerError, fmt.Errorf("Could not get GC Task: %w", err))
	}
	gcTask.HistoricisedTimestamp = time.Now()
	gcTask.Status = gcStatus
	update := bson.M{"$set": gcTask}
	filter := bson.M{"_id": gcTask.ID}

	_, err = s.mongodb.Get().Collection(model.GCCollection.String()).UpdateOne(ctx, filter, update)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", err))
		}
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't remove document: %w", err))
	}
	return nil
}

func (s *CleanupService) updateESGCStatus(ctx context.Context, gcTask *model.GCTask, gcStatus string) error {
	gcTask, err := s.GetESGCTask(ctx, gcTask.ID)
	if err != nil {
		return NewGarbageCollectionError(http.StatusInternalServerError, fmt.Errorf("Could not get GC Task: %w", err))
	}
	gcTask.HistoricisedTimestamp = time.Now()
	gcTask.Status = gcStatus
	update := bson.M{"$set": gcTask}
	filter := bson.M{"_id": gcTask.ID}

	_, err = s.mongodb.Get().Collection(model.ESGCCollection.String()).UpdateOne(ctx, filter, update)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", err))
		}
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't remove document: %w", err))
	}
	return nil
}

func (s *CleanupService) updateFailedGCStatusUpdate(ctx context.Context, gcTask *model.GCTask, err error) {
	taskUpdateCtx, taskUpdateCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	zerolog.Ctx(taskUpdateCtx).Error().Str("gcTaskId", gcTask.ID.Hex()).Err(err)
	defer taskUpdateCtxCancel()
	updateErr := s.updateGCStatus(taskUpdateCtx, gcTask, model.GCFailed)
	if updateErr != nil {
		zerolog.Ctx(context.Background()).Error().Err(NewGarbageCollectionError(http.StatusInternalServerError, fmt.Errorf("Failed to update GC status: %w", updateErr)))
	}
}

func (s *CleanupService) updateFailedESGCStatusUpdate(ctx context.Context, gcTask *model.GCTask, err error) {
	taskUpdateCtx, taskUpdateCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	zerolog.Ctx(taskUpdateCtx).Error().Str("gcTaskId", gcTask.ID.Hex()).Err(err)
	defer taskUpdateCtxCancel()
	updateErr := s.updateESGCStatus(taskUpdateCtx, gcTask, model.GCFailed)
	if updateErr != nil {
		zerolog.Ctx(context.Background()).Error().Err(NewGarbageCollectionError(http.StatusInternalServerError, fmt.Errorf("Failed to update GC status: %w", updateErr)))
	}
}

func (s *CleanupService) RunGarbageCollection(ctx context.Context, fromTimestamp time.Time, gcTask *model.GCTask) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	allCollectionsCursor, err := s.mongodb.Get().ListCollections(ctx, bson.M{})
	if err != nil {
		s.updateFailedGCStatusUpdate(ctx, gcTask, err)
		return
	}
	defer allCollectionsCursor.Close(ctx)

	err = s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		filter := bson.M{"historicised_timestamp": bson.M{"$lt": fromTimestamp}}

		for allCollectionsCursor.Next(sessionContext) {
			collectionInfo := bson.D{}
			sessionError = allCollectionsCursor.Decode(&collectionInfo)
			if sessionError != nil {
				return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", sessionError))
			}
			colName := collectionInfo.Map()["name"].(string)
			var deleteResult *mongo.DeleteResult
			deleteResult, sessionError = s.mongodb.Get().Collection(colName).DeleteMany(sessionContext, filter)
			if sessionError != nil {
				return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't delete documents: %w", sessionError))
			}
			zerolog.Ctx(sessionContext).Info().
				Int64("deletedCount", deleteResult.DeletedCount).
				Str("collection", colName).
				Str("fromTimestamp", fromTimestamp.String()).
				Msg("Removed audit documents older than")
		}
		return nil
	})
	if err != nil {
		s.updateFailedGCStatusUpdate(ctx, gcTask, err)
		return
	}
	zerolog.Ctx(ctx).Info().Str("gcTaskId", gcTask.ID.Hex()).Msg("GC Task finished successfully")
	taskUpdateCtx, taskUpdateCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer taskUpdateCtxCancel()
	err = s.updateGCStatus(taskUpdateCtx, gcTask, model.GCCompleted)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(NewGarbageCollectionError(http.StatusInternalServerError, fmt.Errorf("Failed to update GC status: %w", err)))
	}
}

func (s *CleanupService) GetHotStorageView(ctx context.Context) (*model.HotStorageView, error) {
	if s.kubeClient == nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Kube config not specified"))
	}
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	filter := bson.M{}
	allCollectionsCursor, err := s.mongodb.Get().ListCollections(mongoCtx, filter)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't list collections: %w", err))
	}
	defer allCollectionsCursor.Close(ctx)

	hotStorageView := &model.HotStorageView{}

	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	api := s.kubeClient.CoreV1()
	pvc, err := api.PersistentVolumeClaims(namespace).Get(s.mongoPVC, metav1.GetOptions{})
	if err != nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Couldn't get pvc: %w", err))
	}
	resourceStorage := pvc.Spec.Resources.Requests[v1.ResourceStorage]
	hotStorageView.Total = resourceStorage.Value()

	cmd := []string{
		"sh",
		"-c",
		fmt.Sprintf("du -sb %s", s.mongoDataPath),
	}

	req := s.kubeClient.CoreV1().RESTClient().Post().
		Resource("pods").Name(s.mongoPod).
		Namespace(namespace).SubResource("exec")
	option := &v1.PodExecOptions{
		Command: cmd,
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}
	req.VersionedParams(
		option,
		scheme.ParameterCodec,
	)
	exec, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Cannot get kube executor: %w", err))
	}
	var stdOutbuf bytes.Buffer
	var stdErrbuf bytes.Buffer
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdOutbuf,
		Stderr: &stdErrbuf,
	})
	if err != nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to kube execute command: %w", err))
	}
	usedMem, err := strconv.ParseInt(strings.Fields(stdOutbuf.String())[0], 10, 64)
	if err != nil {
		return nil, NewCannotGetDiskUsageError(http.StatusInternalServerError, fmt.Errorf("Failed to get pvc used disk space: %w", err))
	}
	hotStorageView.Used = usedMem
	return hotStorageView, nil
}

func (s *CleanupService) GetEsHotStorageView(ctx context.Context) (*model.HotStorageView, error) {
	if s.kubeClient == nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Kube config not specified"))
	}

	hotStorageView := &model.HotStorageView{}

	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	api := s.kubeClient.CoreV1()
	pvc, err := api.PersistentVolumeClaims(namespace).Get(s.esPVC, metav1.GetOptions{})
	if err != nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Couldn't get pvc: %w", err))
	}
	resourceStorage := pvc.Spec.Resources.Requests[v1.ResourceStorage]
	hotStorageView.Total = resourceStorage.Value()

	cmd := []string{
		"sh",
		"-c",
		fmt.Sprintf("du -sb %s", s.esDataPath),
	}

	req := s.kubeClient.CoreV1().RESTClient().Post().
		Resource("pods").Name(s.esPod).
		Namespace(namespace).SubResource("exec")
	option := &v1.PodExecOptions{
		Command: cmd,
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}
	req.VersionedParams(
		option,
		scheme.ParameterCodec,
	)
	exec, err := remotecommand.NewSPDYExecutor(s.restConfig, "POST", req.URL())
	if err != nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Cannot get kube executor: %w", err))
	}
	var stdOutbuf bytes.Buffer
	var stdErrbuf bytes.Buffer
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdOutbuf,
		Stderr: &stdErrbuf,
	})
	if err != nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Failed to kube execute command: %w", err))
	}
	usedMem, err := strconv.ParseInt(strings.Fields(stdOutbuf.String())[0], 10, 64)
	if err != nil {
		return nil, NewCannotGetDiskUsageError(http.StatusInternalServerError, fmt.Errorf("Failed to get pvc used disk space: %w", err))
	}
	hotStorageView.Used = usedMem
	return hotStorageView, nil
}

func (s *CleanupService) RunGarbageEsCollection(ctx context.Context, DaysOffset int, gcTask *model.GCTask) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	mongoDB := s.mongodb.Get()
	err := mongoDB.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		url := fmt.Sprintf("http://%s:%s/*-*/_delete_by_query?pretty", s.elasticOpts.Host, s.elasticOpts.Port)

		body := fmt.Sprintf(`{
    "query": {
        "range": {
            "@timestamp": {
                "lt": "now-%dd",
                "format": "epoch_millis"
            }
        }
	}
}`, DaysOffset)
		data, _ := json.Marshal(body)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
		if err != nil {
			return NewConnectionError(http.StatusInternalServerError, fmt.Errorf("failed to prepare scan all request to Harbor: %w", err))
		}
		req.Header.Add("Content-Type", "application/json")
		req.SetBasicAuth(s.elasticOpts.Username, s.elasticOpts.Password)

		httpClient := http.Client{}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr

		_, err = httpClient.Do(req.WithContext(ctx))
		if err != nil {
			return NewHTTPResponseError(http.StatusInternalServerError, fmt.Errorf("failed to send delete all index request to elastic: %w", err))

		}
		return nil
	})
	if err != nil {
		s.updateFailedESGCStatusUpdate(ctx, gcTask, err)
		return
	}
	taskUpdateCtx, taskUpdateCtxCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer taskUpdateCtxCancel()
	err = s.updateESGCStatus(taskUpdateCtx, gcTask, model.GCCompleted)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(NewGarbageCollectionError(http.StatusInternalServerError, fmt.Errorf("Failed to update GC status: %w", err)))
	}
}

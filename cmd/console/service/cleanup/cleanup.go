package cleanup

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type CleanupService struct {
	mongodb       *mongo.Database
	mongoPVC      string
	mongoPod      string
	mongoDataPath string
	kubeClient    *kubernetes.Clientset
	restConfig    *rest.Config
}

func NewCleanupService(
	mongodb *mongo.Database,
	mongoPVC string,
	mongoPod string,
	mongoDataPath string,
) *CleanupService {
	return &CleanupService{
		mongodb:       mongodb,
		mongoPVC:      mongoPVC,
		mongoPod:      mongoPod,
		mongoDataPath: mongoDataPath,
		kubeClient:    nil,
		restConfig:    nil,
	}
}

// OnKubeConfigUpdate should be called e.g. when cluster modified or added
// When cluster deleted, set kubeClient to nil.
func (s *CleanupService) OnKubeConfigUpdate(newClient *kubernetes.Clientset, restConfig *rest.Config) {
	s.kubeClient = newClient
	s.restConfig = restConfig
}

func (s *CleanupService) RunGarbageCollection(ctx context.Context, fromTimestamp time.Time) error {
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	filter := bson.M{}
	allCollectionsCursor, err := s.mongodb.ListCollections(mongoCtx, filter)
	if err != nil {
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't list collections: %w", err))
	}
	defer allCollectionsCursor.Close(ctx)

	filter = bson.M{"historicised_timestamp": bson.M{"$lt": fromTimestamp}}

	for allCollectionsCursor.Next(ctx) {
		collectionInfo := bson.D{}
		err := allCollectionsCursor.Decode(&collectionInfo)
		if err != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		mongoColCtx, mongoColCtxCancel := context.WithTimeout(ctx, time.Second*60)
		defer mongoColCtxCancel()
		colName := collectionInfo.Map()["name"].(string)
		deleteResult, err := s.mongodb.Collection(colName).DeleteMany(mongoColCtx, filter)
		if err != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to remove documents: %w", err))
		}
		logging.GetLogger().Info().
			Int64("deletedCount", deleteResult.DeletedCount).
			Str("collection", colName).
			Str("fromTimestamp", fromTimestamp.String()).
			Msg("Removed audit documents older than")
	}
	return nil
}

func (s *CleanupService) GetHotStorageView(ctx context.Context) (*model.HotStorageView, error) {
	if s.kubeClient == nil {
		return nil, NewKubernetesError(http.StatusInternalServerError, fmt.Errorf("Kube config not specified"))
	}
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	filter := bson.M{}
	allCollectionsCursor, err := s.mongodb.ListCollections(mongoCtx, filter)
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

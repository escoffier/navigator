package processingcenter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/olivere/elastic/v7"

	"gitlab.com/piccolo_su/vegeta/cmd/data/util"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	service *Service
)

type MockPodService struct {
}

func (s *MockPodService) CheckPodExist(_ context.Context, _ *model.PodInfo) (bool, error) {
	return false, nil
}
func (s *MockPodService) IsolatePod(_ context.Context, pods []*model.PodInfo) (successfulPods, isolatedPods, deletedPods []*model.PodInfo) {
	return pods, nil, nil
}
func (s *MockPodService) CancelIsolatePod(_ context.Context, pods []*model.PodInfo) (successfulPods []*model.PodInfo) {
	return pods
}
func (s *MockPodService) DeletePods(_ context.Context, pods []*model.PodInfo) (successfulPods, notFoundPods []*model.PodInfo) {
	return pods, nil
}

func initService(t *testing.T) {
	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")

	db, err := util.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.Get().AutoMigrate(&model.ProcessingAction{}); err != nil {
		t.Fatal(err)
	}

	esCli, err := elastic.NewClient(elastic.SetSniff(false))
	if err != nil {
		t.Fatal(err)
	}

	redisCli := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
	service = newService(&ServiceComponent{
		DB:       db,
		EsCli:    esCli,
		RedisCli: redisCli,
	})
	service.podService = &MockPodService{}
}

func TestService_CreateProcessingRecord(t *testing.T) {
	initService(t)
	id, partial, err := service.CreateProcessingRecord(context.TODO(), &AddProcessingRecordArg{
		EventID: 102,
		OpType:  ProcessingTypePodDeletion,
		Action:  ProcessingActionDelete,
		Object:  []string{"cluster@namespace@pod1", "cluster@namespace@pod2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(id, partial)

	id, partial, err = service.CreateProcessingRecord(context.TODO(), &AddProcessingRecordArg{
		EventID: 103,
		OpType:  ProcessingTypePodIsolation,
		Action:  ProcessingActionIsolate,
		Object:  []string{"cluster@namespace@pod1", "cluster@namespace@pod2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(id, partial)
}

func TestService_UpdateProcessingRecordStatus(t *testing.T) {
	initService(t)
	id, _, err := service.CreateProcessingRecord(context.TODO(), &AddProcessingRecordArg{
		EventID: 102,
		OpType:  ProcessingTypePodIsolation,
		Action:  ProcessingActionIsolate,
		Object:  []string{"cluster@namespace@pod1", "cluster@namespace@pod2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(id)
	time.Sleep(time.Second * 2)
	err = service.UpdateProcessingRecordStatus(context.TODO(), id, ProcessingStatusEnd)
	if err != nil {
		t.Fatal(err)
	}
}

func TestService_AddProcessingAction(t *testing.T) {
	initService(t)
	action, _, err := service.AddProcessingAction(context.TODO(), &AddProcessingActionArg{
		RecordID: "6f0e2f71ff9c421e943a4585a811ff55",
		Object:   []string{"cluster@namespace@pod1", "cluster@namespace@pod2"},
		Action:   ProcessingActionCancelIsolation,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(action)
}

func TestService_GetRecordDetail(t *testing.T) {
	initService(t)
	detail, err := service.GetRecordDetail(context.TODO(), "cfd5a52adc3e4a03add568bde6f1053f")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(detail)
	for _, obj := range detail.Object {
		t.Log(obj)
	}
	for _, action := range detail.Actions {
		t.Log(action)
	}
}

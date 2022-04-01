package processingcenter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/processingcenter/podservice"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	instance *Service
	once     sync.Once
)

func GetService(_ context.Context) (*Service, bool) {
	return instance, instance != nil
}

func Init(component *ServiceComponent) error {
	if component == nil {
		return errors.New("illegal argument")
	}
	once.Do(func() {
		instance = newService(component)
	})
	return nil
}

const (
	ProcessingTypePodIsolation = "PodIsolation"
	ProcessingTypePodDeletion  = "PodDeletion"

	ProcessingActionIsolate         = "isolate"
	ProcessingActionCancelIsolation = "cancelIsolation"
	ProcessingActionDelete          = "delete"

	ProcessingStatusEnd      = "end"
	ProcessingStatusIsolated = "isolated"

	PodStatusNotExist       = "notExist"
	PodStatusIsolated       = "isolated"
	PodStatusCancelIsolated = "cancelIsolated"
)

type podService interface {
	CheckPodExist(ctx context.Context, pod *model.PodInfo) (bool, error)
	IsolatePod(ctx context.Context, pods []*model.PodInfo) (successfulPods, isolatedPods, deletedPods []*model.PodInfo)
	CancelIsolatePod(ctx context.Context, pods []*model.PodInfo) (successfulPods []*model.PodInfo)
	DeletePods(ctx context.Context, pods []*model.PodInfo) (successfulPods, notFoundPods []*model.PodInfo)
}

type Service struct {
	podService            podService
	db                    *databases.RDBInstance
	esCli                 *elastic.ESClient
	processingIndexPrefix string
	recordSyncHash        map[string]struct{}
	recordSyncLock        sync.Mutex
}

type ServiceComponent struct {
	DB              *databases.RDBInstance
	EsCli           *elastic.ESClient
	RedisCli        *redis.Client
	MicroSegBaseURL string
}

const (
	EnvProcessingIndexPrefix     = "PROCESSING_INDEX_PREFIX"
	DefaultProcessingIndexPrefix = "processing_"
)

func newService(component *ServiceComponent) *Service {
	return &Service{
		podService:            podservice.NewService(component.RedisCli, component.MicroSegBaseURL),
		db:                    component.DB,
		esCli:                 component.EsCli,
		processingIndexPrefix: util.GetEnvWithDefault(EnvProcessingIndexPrefix, DefaultProcessingIndexPrefix),
		recordSyncHash:        make(map[string]struct{}),
	}
}

type AddProcessingRecordArg struct {
	EventID int32    `json:"eventID"`
	OpType  string   `json:"opType"`
	Action  string   `json:"action"`
	Object  []string `json:"object"`
}

var (
	ErrInvalidPodInfo        = errors.New("invalid pod info")
	ErrPodNotExist           = errors.New("pod not exist")
	ErrPodIsolated           = errors.New("pod is already isolated")
	ErrPaginationExceedLimit = errors.New("pagination exceed limit")
	ErrInvalidOp             = errors.New("invalid op")
	ErrInternalError         = errors.New("internal error")
	ErrRecordNotFound        = errors.New("record not found")
	ErrUpdateConflict        = errors.New("update conflict")
)

func (s *Service) CreateProcessingRecord(ctx context.Context, arg *AddProcessingRecordArg) (id string, partial bool, err error) {
	pods, err := parsePods(arg.Object)
	if err != nil {
		return "", false, err
	}
	switch arg.OpType {
	case ProcessingTypePodIsolation:
		if arg.Action != ProcessingActionIsolate {
			return "", false, ErrInvalidOp
		}

		successfulPods, isolatedPods, deletedPods := s.podService.IsolatePod(ctx, pods)
		if len(successfulPods) == 0 {
			if len(deletedPods) == len(pods) {
				return "", false, ErrPodNotExist
			}

			if len(isolatedPods) > 0 {
				return "", false, ErrPodIsolated
			}

			return "", false, ErrInternalError
		}

		if len(successfulPods) < len(pods) {
			partial = true
		}
		id, err := s.saveProcessingRecord(ctx, arg, encodePods(successfulPods), ProcessingStatusIsolated)
		return id, partial, err
	case ProcessingTypePodDeletion:
		if arg.Action != ProcessingActionDelete {
			return "", false, ErrInvalidOp
		}
		successfulPods, notFoundPods := s.podService.DeletePods(ctx, pods)
		if len(successfulPods) == 0 {
			if len(notFoundPods) == len(pods) {
				return "", false, ErrPodNotExist
			}
			return "", false, ErrInternalError
		}

		if len(successfulPods) < len(pods) {
			partial = true
		}
		id, err := s.saveProcessingRecord(ctx, arg, encodePods(successfulPods), ProcessingStatusEnd)
		return id, partial, err

	default:
		return "", false, ErrInvalidOp
	}
}

func (s *Service) saveProcessingRecord(ctx context.Context, arg *AddProcessingRecordArg, object []string, initialStatus string) (id string, err error) {
	nowTime := time.Now()
	username := model.GetUsernameFromContext(ctx)
	processingRecord := makeProcessingRecord(arg, object, username, initialStatus, nowTime)
	err = dal.SaveProcessingAction(ctx, s.db.Get(), makeProcessingAction(username, arg.Action, processingRecord.ID, object, nowTime))
	if err != nil {
		return "", err
	}

	if esCli, gerr := s.esCli.Get(); gerr == nil {
		err = dal.SaveProcessingRecord(ctx, esCli, s.getProcessingIndexByTime(nowTime), processingRecord)
	}

	return processingRecord.ID, err
}

func makeProcessingRecord(arg *AddProcessingRecordArg, object []string, username, status string, nowTime time.Time) *model.ProcessingRecord {
	return &model.ProcessingRecord{
		ID:         util.GenerateUUIDHex(),
		EventID:    arg.EventID,
		OpType:     arg.OpType,
		UpdatedAt:  util.GetMillisecondTimestampByTime(nowTime),
		Status:     status,
		LastOpUser: username,
		Object:     object,
	}
}

func makeProcessingAction(username, action, recordID string, object []string, nowTime time.Time) *model.ProcessingAction {
	result := &model.ProcessingAction{
		RecordID:  recordID,
		Operation: action,
		Creator:   username,
		CreatedAt: nowTime,
	}
	result.SetObject(object)
	return result
}

func parsePods(object []string) ([]*model.PodInfo, error) {
	dup := make(map[string]struct{})
	var pods = make([]*model.PodInfo, 0, len(object))
	for _, podStr := range object {
		if _, ok := dup[podStr]; ok {
			continue
		}
		dup[podStr] = struct{}{}
		pod, err := parsePodInfo(podStr)
		if err != nil {
			return nil, err
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

func parsePodInfo(podStr string) (info *model.PodInfo, err error) {
	arr := strings.Split(podStr, "@")
	if len(arr) != 3 {
		return nil, ErrInvalidPodInfo
	}

	return &model.PodInfo{Cluster: arr[0], Namespace: arr[1], PodName: arr[2]}, nil
}

func encodePods(pods []*model.PodInfo) []string {
	var result = make([]string, len(pods))
	for i := range pods {
		result[i] = fmt.Sprintf("%s@%s@%s", pods[i].Cluster, pods[i].Namespace, pods[i].PodName)
	}
	return result
}

const (
	MaxPaginationNum = 10000
)

func (s *Service) GetProcessingRecordByID(ctx context.Context, id string) (*model.ProcessingRecord, error) {
	esCli, err := s.esCli.Get()
	if err != nil {
		return nil, err
	}
	record, err := dal.QueryProcessingRecordByID(ctx, esCli, s.getProcessingIndexPattern(), id)
	if err == dal.ErrNotFound {
		return nil, ErrRecordNotFound
	}
	return record, err
}

func (s *Service) GetProcessingRecord(ctx context.Context, arg *model.QueryProcessingRecordArg) (total int64, records []*model.ProcessingRecord, err error) {
	if arg.Limit+arg.Offset > MaxPaginationNum {
		return 0, nil, ErrPaginationExceedLimit
	}

	esCli, err := s.esCli.Get()
	if err != nil {
		return 0, nil, err
	}
	return dal.QueryProcessingRecord(ctx, esCli, s.getProcessingIndexPattern(), arg)
}

type AddProcessingActionArg struct {
	RecordID string
	Object   []string
	Action   string
}

func (s *Service) lockRecord(recordID string) error {
	s.recordSyncLock.Lock()
	defer s.recordSyncLock.Unlock()

	if _, ok := s.recordSyncHash[recordID]; ok {
		return ErrUpdateConflict
	}
	s.recordSyncHash[recordID] = struct{}{}
	return nil
}

func (s *Service) releaseRecord(recordID string) {
	s.recordSyncLock.Lock()
	defer s.recordSyncLock.Unlock()
	delete(s.recordSyncHash, recordID)
}

func (s *Service) UpdateProcessingRecordStatus(ctx context.Context, id, status string) error {
	if status != ProcessingStatusEnd {
		// 目前仅支持结束状态
		return ErrInvalidOp
	}

	esCli, err := s.esCli.Get()
	if err != nil {
		return err
	}

	err = s.lockRecord(id)
	if err != nil {
		return err
	}
	defer s.releaseRecord(id)

	record, err := dal.QueryProcessingRecordByID(ctx, esCli, s.getProcessingIndexPattern(), id)
	if err != nil {
		if err == dal.ErrNotFound {
			return ErrRecordNotFound
		}
		return err
	}

	// 仅支持将隔离中状态的记录置为结束
	if record.OpType != ProcessingTypePodIsolation ||
		record.Status != ProcessingStatusIsolated {
		return ErrInvalidOp
	}

	actions, err := dal.GetProcessingActions(ctx, s.db.GetReadDB(), record.ID)
	if err != nil {
		return err
	}

	// 当切仅当所有pod取消隔离或者不存在时可以将记录置为结束
	isolatedPod := calcIsolatedObject(record.Object, actions)
	for podStr := range isolatedPod {
		pod, err := parsePodInfo(podStr)
		if err != nil {
			logging.Get().Error().Msgf("unexpected pod:%s", podStr)
			continue
		}
		exist, err := s.podService.CheckPodExist(ctx, pod)
		if err != nil {
			return err
		}

		if exist {
			return ErrInvalidOp
		}
	}

	return dal.UpdateProcessingRecord(ctx, esCli, s.getProcessingIndexPattern(), &model.ProcessingRecordChange{
		ID:         id,
		UpdatedAt:  util.GetMillisecondTimestampByTime(time.Now()),
		LastOpUser: model.GetUsernameFromContext(ctx),
		Status:     status,
	})
}

func (s *Service) AddProcessingAction(ctx context.Context, arg *AddProcessingActionArg) (*model.ProcessingAction, bool, error) {
	if arg.Action != ProcessingActionCancelIsolation {
		// 目前只支持取消隔离
		return nil, false, ErrInvalidOp
	}

	esCli, err := s.esCli.Get()
	if err != nil {
		return nil, false, err
	}

	err = s.lockRecord(arg.RecordID)
	if err != nil {
		return nil, false, err
	}
	defer s.releaseRecord(arg.RecordID)

	record, err := dal.QueryProcessingRecordByID(ctx, esCli, s.getProcessingIndexPattern(), arg.RecordID)
	if err != nil {
		if err == dal.ErrNotFound {
			return nil, false, ErrRecordNotFound
		}
		return nil, false, err
	}

	if record.OpType != ProcessingTypePodIsolation ||
		record.Status != ProcessingStatusIsolated {
		return nil, false, ErrInvalidOp
	}

	actions, err := dal.GetProcessingActions(ctx, s.db.Get(), record.ID)
	if err != nil {
		return nil, false, err
	}

	isolatedPod := calcIsolatedObject(record.Object, actions)
	var toBeCanceled []string
	for _, pod := range arg.Object {
		if _, ok := isolatedPod[pod]; ok {
			toBeCanceled = append(toBeCanceled, pod)
		}
	}

	if len(toBeCanceled) == 0 {
		return nil, false, ErrInvalidOp
	}

	pods, err := parsePods(toBeCanceled)
	if err != nil {
		return nil, false, ErrInvalidOp
	}

	successPods := s.podService.CancelIsolatePod(ctx, pods)
	if len(successPods) == 0 {
		return nil, false, ErrInternalError
	}

	var partial bool
	if len(successPods) < len(pods) {
		partial = true
	}

	username := model.GetUsernameFromContext(ctx)
	nowTime := time.Now()
	successObj := encodePods(successPods)

	action := makeProcessingAction(username, arg.Action, arg.RecordID, successObj, nowTime)
	err = dal.SaveProcessingAction(ctx, s.db.Get(), action)
	if err != nil {
		return nil, false, err
	}

	for _, pod := range successObj {
		delete(isolatedPod, pod)
	}

	status := ProcessingStatusEnd
	for podStr := range isolatedPod {
		pod, _ := parsePodInfo(podStr)
		if pod == nil {
			logging.Get().Error().Msgf("unexpected podStr:%s", podStr)
			continue
		}
		if exist, err := s.podService.CheckPodExist(ctx, pod); err != nil || exist {
			status = ProcessingStatusIsolated
			break
		}
	}

	err = dal.UpdateProcessingRecord(ctx, esCli, s.getProcessingIndexPattern(), &model.ProcessingRecordChange{
		ID:         arg.RecordID,
		UpdatedAt:  util.GetMillisecondTimestampByTime(nowTime),
		LastOpUser: username,
		Status:     status,
	})
	return action, partial, err
}

func calcIsolatedObject(total []string, actions []*model.ProcessingAction) map[string]struct{} {
	isolatedPod := make(map[string]struct{})
	for _, pod := range total {
		isolatedPod[pod] = struct{}{}
	}
	for _, action := range actions {
		if action.Operation == ProcessingActionCancelIsolation {
			objects := action.GetObjects()
			for _, pod := range objects {
				delete(isolatedPod, pod)
			}
		}
	}
	return isolatedPod
}

func (s *Service) GetRecordDetail(ctx context.Context, recordID string) (*model.ProcessingRecordDisplay, error) {
	esCli, err := s.esCli.Get()
	if err != nil {
		return nil, err
	}
	record, err := dal.QueryProcessingRecordByID(ctx, esCli, s.getProcessingIndexPattern(), recordID)
	if err != nil {
		if err == dal.ErrNotFound {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}

	actions, err := dal.GetProcessingActions(ctx, s.db.GetReadDB(), recordID)
	if err != nil {
		return nil, err
	}

	var object []*model.ObjectDisplay
	if record.OpType == ProcessingTypePodIsolation {
		object, err = s.getIsolationPodStatus(ctx, record.Object, actions)
		if err != nil {
			return nil, err
		}
	} else {
		object = makeDeletionPodStatus(record.Object)
	}

	result := &model.ProcessingRecordDisplay{
		ID:         recordID,
		EventID:    record.EventID,
		OpType:     record.OpType,
		Status:     record.Status,
		LastOpUser: record.LastOpUser,
		Object:     object,
		UpdatedAt:  record.UpdatedAt,
		Actions:    make([]*model.ActionDisplay, 0, len(actions)),
	}
	for _, action := range actions {
		result.Actions = append(result.Actions, &model.ActionDisplay{
			RecordID:  recordID,
			Action:    action.Operation,
			User:      action.Creator,
			Object:    action.GetObjects(),
			Timestamp: util.GetMillisecondTimestampByTime(action.CreatedAt),
		})
	}

	return result, nil
}

func (s *Service) getIsolationPodStatus(ctx context.Context, object []string, actions []*model.ProcessingAction) ([]*model.ObjectDisplay, error) {
	canceledIsolatedPod := make(map[string]struct{})
	for _, action := range actions {
		if action.Operation == ProcessingActionCancelIsolation {
			objects := action.GetObjects()
			for _, pod := range objects {
				canceledIsolatedPod[pod] = struct{}{}
			}
		}
	}

	var result = make([]*model.ObjectDisplay, 0, len(object))
	for _, podStr := range object {
		pod, err := parsePodInfo(podStr)
		if err != nil {
			return nil, err
		}
		exist, err := s.podService.CheckPodExist(ctx, pod)
		if err != nil {
			return nil, err
		}

		var item = &model.ObjectDisplay{
			Key: podStr,
		}

		if !exist {
			item.Status = PodStatusNotExist
		} else if _, ok := canceledIsolatedPod[podStr]; ok {
			item.Status = PodStatusCancelIsolated
		} else {
			item.Status = PodStatusIsolated
		}

		result = append(result, item)
	}

	return result, nil
}

func makeDeletionPodStatus(object []string) []*model.ObjectDisplay {
	var result = make([]*model.ObjectDisplay, len(object))
	for i := range object {
		result[i] = &model.ObjectDisplay{Key: object[i], Status: PodStatusNotExist}
	}
	return result
}

func (s *Service) getProcessingIndexPattern() string {
	return fmt.Sprintf("%s*", s.processingIndexPrefix)
}

func (s *Service) getProcessingIndexByTime(t time.Time) string {
	return fmt.Sprintf("%s%s", s.processingIndexPrefix, t.Format("2006-01-02"))
}

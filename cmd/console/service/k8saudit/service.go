package k8saudit

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	pkgelastic "gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"
	"gitlab.com/security-rd/go-pkg/syslog"
	"go.uber.org/atomic"
	"gorm.io/gorm"
)

var (
	instance       atomic.Value // *Service
	once           sync.Once
	initServiceErr error
)
var (
	ErrESDocumentNotFound   = errors.New("es document not found")
	ErrInvalidSyslogSetting = errors.New("invalid syslog setting")
)

func Init(rdb *databases.RDBInstance, esCli *pkgelastic.ESClient) error {
	if rdb == nil || esCli == nil {
		return errors.New("unexpected empty pointer")
	}
	once.Do(func() {
		var service *Service
		service, initServiceErr = newService(rdb, esCli)
		if initServiceErr == nil {
			instance.Store(service)
		}
	})

	return initServiceErr
}

func GetServiceInstance() (*Service, bool) {
	service := instance.Load()
	if service == nil {
		return nil, false
	}

	return service.(*Service), true
}

func newService(rdb *databases.RDBInstance, esCli *pkgelastic.ESClient) (*Service, error) {
	syslogHandler, err := syslog.NewHandler(&store{db: rdb})
	if err != nil {
		return nil, err
	}
	s := &Service{
		db:            rdb,
		esCli:         esCli,
		ch:            make(chan []*model.AuditRecord, 1000),
		indexPrefix:   util.GetEnvWithDefault(AuditIndexPrefixEnv, DefaultAuditIndexPrefix),
		syslogHandler: syslogHandler,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	conf, err := s.getAuditConfig(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("get audit config fail")
		conf = model.DefaultAuditLogConf
	}
	s.logEnabled.Store(conf.LogEnabled)

	go s.asyncRecordLog()
	go s.asyncWatchConfig()
	return s, nil
}

type Service struct {
	esCli         *pkgelastic.ESClient
	db            *databases.RDBInstance
	ch            chan []*model.AuditRecord
	indexPrefix   string
	logEnabled    atomic.Bool
	syslogHandler *syslog.Handler
}

func (s *Service) RecordAuditLog(ctx context.Context, records []*model.AuditRecord) error {
	if !s.logEnabled.Load() {
		logging.Get().Debug().Msg("ignore k8s audit log")
		return nil
	}
	select {
	case s.ch <- records:
		return nil
	case <-ctx.Done():
		logging.Get().Error().Msgf("AuditWebhook timeout")
		return ctx.Err()
	}
}

type GetAuditLogArg struct {
	OffsetID       string
	Filter         map[string]string
	StartTimestamp int64
	EndTimestamp   int64
	Limit          int
	Asc            bool
}

const (
	stageTimestampKey = "StageTimestamp"
)

func (s *Service) GetAuditLog(ctx context.Context, arg *GetAuditLogArg) ([]*model.AuditDisplay, error) {
	esCli, err := s.esCli.Get()
	if err != nil {
		return nil, err
	}
	searchService := esCli.Search(fmt.Sprintf("%s*", s.indexPrefix)).
		Sort(stageTimestampKey, arg.Asc).Sort("_id", arg.Asc).Size(arg.Limit)

	var queries []elastic.Query
	if arg.StartTimestamp > 0 && arg.EndTimestamp >= arg.StartTimestamp {
		queries = append(queries, elastic.NewRangeQuery(stageTimestampKey).
			Gte(util.GetTimeByMillisecondTimestamp(arg.StartTimestamp)).
			Lte(util.GetTimeByMillisecondTimestamp(arg.EndTimestamp)))
	}

	for k, v := range arg.Filter {
		if k != "" && v != "" {
			queries = append(queries, elastic.NewMatchQuery(k, v))
		}
	}

	if len(queries) > 0 {
		searchService = searchService.Query(elastic.NewBoolQuery().Must(queries...))
	}

	if arg.OffsetID != "" {
		record, err := s.GetRecordByID(ctx, arg.OffsetID)
		if err == nil {
			searchService = searchService.SearchAfter(record.StageTimestamp, arg.OffsetID)
		} else if err != ErrESDocumentNotFound {
			return nil, err
		}
	}

	searchResult, err := searchService.Do(ctx)
	if err != nil {
		return nil, err
	}

	var result = make([]*model.AuditDisplay, 0, len(searchResult.Hits.Hits))
	for _, item := range searchResult.Hits.Hits {
		record, err := parseRecord(item)
		if err != nil {
			logging.Get().Err(err).Msg("parse k8s audit log fail")
			continue
		}
		result = append(result, record.ToDisplay(item.Id))
	}

	return result, nil
}

func (s *Service) GetRecordByID(ctx context.Context, id string) (*model.AuditRecord, error) {
	esCli, err := s.esCli.Get()
	if err != nil {
		return nil, err
	}
	rsp, err := esCli.Search().Index(fmt.Sprintf("%s*", s.indexPrefix)).
		Query(elastic.NewTermQuery("_id", id)).Do(ctx)
	if err != nil {
		return nil, err
	}

	if len(rsp.Hits.Hits) != 1 {
		return nil, ErrESDocumentNotFound
	}

	return parseRecord(rsp.Hits.Hits[0])
}

func parseRecord(item *elastic.SearchHit) (*model.AuditRecord, error) {
	var record model.AuditRecord
	var err = json.Unmarshal(item.Source, &record)
	return &record, err
}

const (
	auditConfigKey = "k8s-audit-log-conf"
)

func (s *Service) GetAuditConfig(ctx context.Context) (*model.AuditLogConfig, error) {
	return s.getAuditConfig(ctx)
}

func (s *Service) getAuditConfig(ctx context.Context) (*model.AuditLogConfig, error) {
	conf, err := dal.GetConfig(ctx, s.db.GetReadDB(), auditConfigKey)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	if conf == nil || err == gorm.ErrRecordNotFound {
		return model.DefaultAuditLogConf, nil
	}

	var logConf model.AuditLogConfig
	err = json.Unmarshal(conf.Config, &logConf)
	if err != nil {
		logging.Get().Err(err).Msgf("parse audit log fail, conf:%s", string(conf.Config))
		return model.DefaultAuditLogConf, nil
	}

	return &logConf, nil
}

func (s *Service) SetAuditConfig(ctx context.Context, config *model.AuditLogConfig) error {
	confJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	err = dal.SetConfig(ctx, s.db.Get(), auditConfigKey, confJSON)
	if err == nil {
		s.logEnabled.Store(config.LogEnabled)
	}
	return err
}

const (
	recordTimeout = time.Second * 3
)

func (s *Service) asyncRecordLog() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	for {
		records := <-s.ch
		err := s.recordAuditLog(records)
		if err != nil {
			logging.Get().Err(err).Msg("recordAuditLog fail")
			continue
		}

		s.exportToSyslog(records)
	}
}

func (s *Service) recordAuditLog(records []*model.AuditRecord) error {
	esCli, err := s.esCli.Get()
	if err != nil {
		return err
	}
	indexStr := s.indexPrefix + time.Now().Format("2006-01-02")
	bulkRequest := esCli.Bulk()
	for _, event := range records {
		if event.RequestObject != nil {
			requestContent, _ := event.RequestObject.MarshalJSON()
			event.RequestContent = string(requestContent)
			event.RequestObject = nil
		}
		if event.ResponseObject != nil {
			responseContent, _ := event.ResponseObject.MarshalJSON()
			event.ResponseContent = string(responseContent)
			event.ResponseObject = nil
		}

		bulkRequest.Add(elastic.NewBulkIndexRequest().Index(indexStr).Doc(event))
	}

	ctx, cancel := context.WithTimeout(context.Background(), recordTimeout)
	rsp, err := bulkRequest.Do(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("send es bulk request fail, err:%w", err)
	}

	if rsp.Errors {
		failedItems := rsp.Failed()
		for _, item := range failedItems {
			if item != nil && item.Error != nil {
				logging.Get().Error().Msgf("record audit log fail, reason:%s, type:%s, causedBy:%s, resourceType:%s, resourceID:%s, rootCause:%+v",
					item.Error.Reason, item.Error.Type, item.Error.CausedBy, item.Error.ResourceType, item.Error.ResourceId, item.Error.RootCause)
			}
		}
		return errors.New("record audit log fail")
	}

	return nil
}

func (s *Service) exportToSyslog(records []*model.AuditRecord) {
	for _, event := range records {
		eventJSON, err := json.Marshal(event.Event)
		if err != nil {
			logging.Get().Err(err).Msg("json marshal event fail")
			continue
		}

		if err = s.syslogHandler.Log(eventJSON); err != nil {
			logging.Get().Err(err).Msg("write syslog fail")
		}
	}
}

const (
	configWatchInterval = time.Second * 10
)

func (s *Service) asyncWatchConfig() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), configWatchInterval/2)
		conf, err := s.getAuditConfig(ctx)
		cancel()
		if err == nil {
			s.logEnabled.Store(conf.LogEnabled)
		} else {
			logging.Get().Err(err).Msg("get audit config fail")
		}
	}
}

func (s *Service) GetSyslogSettings(ctx context.Context) (*pb.SyslogSetting, error) {
	return s.syslogHandler.GetSetting(ctx)
}

func (s *Service) UpdateSyslogSettings(ctx context.Context, setting *pb.SyslogSetting) error {
	err := s.syslogHandler.UpdateSetting(ctx, setting)
	if err == syslog.ErrInvalidSyslogSetting {
		return ErrInvalidSyslogSetting
	}
	return err
}

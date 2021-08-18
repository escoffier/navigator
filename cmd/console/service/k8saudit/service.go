package k8saudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/olivere/elastic/v7"
	"go.uber.org/atomic"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	syslog2 "gitlab.com/piccolo_su/vegeta/pkg/syslog"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	instance       atomic.Value // *Service
	once           sync.Once
	initServiceErr error
)

func Init(postgresDB *rdbtools.GormWrapper, esCli *elastic.Client) error {
	if postgresDB == nil || esCli == nil {
		return errors.New("unexpected empty pointer")
	}
	once.Do(func() {
		var service *Service
		service, initServiceErr = newService(postgresDB, esCli)
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

func newService(postgresDB *rdbtools.GormWrapper, esCli *elastic.Client) (*Service, error) {
	s := &Service{
		db:          postgresDB,
		esCli:       esCli,
		ch:          make(chan []*model.AuditRecord, 1000),
		indexPrefix: util.GetEnvWithDefault(AuditIndexPrefixEnv, DefaultAuditIndexPrefix),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	conf, err := s.getAuditConfig(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get audit config fail")
		conf = model.DefaultAuditLogConf
	}
	s.logEnabled.Store(conf.LogEnabled)

	if util.GetBoolValWithDefault(SyslogEnableEnv, DefaultSyslogEnable) {
		writer, _err := syslog2.NewWriter(&syslog2.Conf{
			Network:  util.GetEnvWithDefault(SyslogNetworkEnv, DefaultSyslogNetwork),
			Addr:     util.GetEnvWithDefault(SyslogServerAddrEnv, ""),
			Facility: uint8(util.GetIntValWithDefault(SyslogFacilityEnv, DefaultSyslogFacility)),
			Severity: uint8(util.GetIntValWithDefault(SyslogSeverityEnv, DefaultSyslogSeverity)),
			Tag:      util.GetEnvWithDefault(SyslogTagEnv, DefaultSyslogTag),
		})
		if _err != nil {
			logging.GetLogger().Err(_err).Msgf("new sys log handler fail")
		} else {
			s.writer = writer
		}
	}

	go s.asyncRecordLog()
	go s.asyncWatchConfig()
	return s, nil
}

type Service struct {
	esCli       *elastic.Client
	db          *rdbtools.GormWrapper
	ch          chan []*model.AuditRecord
	indexPrefix string
	logEnabled  atomic.Bool
	writer      *syslog.Writer
}

func (s *Service) RecordAuditLog(ctx context.Context, records []*model.AuditRecord) error {
	if !s.logEnabled.Load() {
		logging.GetLogger().Debug().Msg("ignore k8s audit log")
		return nil
	}
	select {
	case s.ch <- records:
		return nil
	case <-ctx.Done():
		logging.GetLogger().Error().Msgf("AuditWebhook timeout")
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
	searchService := s.esCli.Search(fmt.Sprintf("%s*", s.indexPrefix)).
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
			logging.GetLogger().Err(err).Msg("parse k8s audit log fail")
			continue
		}
		result = append(result, record.ToDisplay(item.Id))
	}

	return result, nil
}

var (
	ErrESDocumentNotFound = fmt.Errorf("es document not found")
)

func (s *Service) GetRecordByID(ctx context.Context, id string) (*model.AuditRecord, error) {
	rsp, err := s.esCli.Search().Index(fmt.Sprintf("%s*", s.indexPrefix)).
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
	ConfigKey = "k8s-audit-log-conf"
)

func (s *Service) GetAuditConfig(ctx context.Context) (*model.AuditLogConfig, error) {
	return s.getAuditConfig(ctx)
}

func (s *Service) getAuditConfig(ctx context.Context) (*model.AuditLogConfig, error) {
	conf, err := dal.GetConfig(ctx, s.db, ConfigKey)
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return model.DefaultAuditLogConf, nil
	}

	var logConf model.AuditLogConfig
	err = json.Unmarshal(conf.Config, &logConf)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("parse audit log fail, conf:%s", string(conf.Config))
		return model.DefaultAuditLogConf, nil
	}

	return &logConf, nil
}

func (s *Service) SetAuditConfig(ctx context.Context, config *model.AuditLogConfig) error {
	confJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	err = dal.SetConfig(ctx, s.db, ConfigKey, confJSON)
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
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	for {
		records := <-s.ch
		err := s.recordAuditLog(records)
		if err != nil {
			logging.GetLogger().Err(err).Msg("recordAuditLog fail")
			continue
		}

		s.exportToSyslog(records)
	}
}

func (s *Service) recordAuditLog(records []*model.AuditRecord) error {
	indexStr := s.indexPrefix + time.Now().Format("2006-01-02")
	bulkRequest := s.esCli.Bulk()
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
				logging.GetLogger().Error().Msgf("record audit log fail, reason:%s, type:%s, causedBy:%s, resourceType:%s, resourceID:%s, rootCause:%+v",
					item.Error.Reason, item.Error.Type, item.Error.CausedBy, item.Error.ResourceType, item.Error.ResourceId, item.Error.RootCause)
			}
		}
		return errors.New("record audit log fail")
	}

	return nil
}

func (s *Service) exportToSyslog(records []*model.AuditRecord) {
	if s.writer == nil {
		return
	}

	for _, event := range records {
		eventJSON, err := json.Marshal(event.Event)
		if err != nil {
			logging.GetLogger().Err(err).Msg("json marshal event fail")
			continue
		}

		if _, err = s.writer.Write(eventJSON); err != nil {
			logging.GetLogger().Err(err).Msg("write syslog fail")
		}
	}
}

const (
	configWatchInterval = time.Second * 10
)

func (s *Service) asyncWatchConfig() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	ticker := time.NewTicker(configWatchInterval)
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), configWatchInterval/2)
		conf, err := s.getAuditConfig(ctx)
		cancel()
		if err == nil {
			s.logEnabled.Store(conf.LogEnabled)
		} else {
			logging.GetLogger().Err(err).Msg("get audit config fail")
		}
	}
}

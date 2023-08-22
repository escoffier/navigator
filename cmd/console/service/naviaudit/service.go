package naviaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/pb"
	"gitlab.com/security-rd/go-pkg/syslog"
	"sync"

	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	pkgelastic "gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
)

const timeStampKey = "Timestamp"

var (
	instance                *Service
	rlOnce                  sync.Once
	ErrESDocumentNotFound   = errors.New("es document not found")
	ErrInvalidSyslogSetting = errors.New("invalid syslog setting")
	// verbLangDic           = map[string]string{
	// 	"编辑":    "Edit",
	// 	"新增":    "Create",
	// 	"删除":    "Delete",
	// 	"启用":    "Enable",
	// 	"停用":    "Disable",
	// 	"启用/停用": "Enable/Disable",
	// 	"导出":    "Import",
	// 	"上传":    "Upload",
	// 	"发起处置":  "Process",
	// }
)

type Service struct {
	esCli       *pkgelastic.ESClient
	indexPrefix string
	// add mhx syslog
	db            *databases.RDBInstance
	syslogHandler *syslog.Handler
}

type QueryNaviAuditLogOpt struct {
	OffsetID       string
	Filter         map[string]string
	StartTimestamp int64
	EndTimestamp   int64
	Limit          int
	Asc            bool
	Lang           string
}

type Resp struct {
	ID        string
	Time      int64
	UserName  string
	Ip        string
	Operation string
	Detail    string
	Status    string
	Err       string
}

func InitService(ecCli *pkgelastic.ESClient, rdb *databases.RDBInstance) (err error) {
	rlOnce.Do(func() {
		instance, err = newService(ecCli, rdb)
		if err != nil {
			return
		}
	})
	return nil
}

func newService(client *pkgelastic.ESClient, rdb *databases.RDBInstance) (*Service, error) {
	syslogHandler, err := syslog.NewHandler(&Store{Db: rdb})
	if err != nil {
		return nil, err
	}
	return &Service{esCli: client, indexPrefix: "navi-audit-", db: rdb, syslogHandler: syslogHandler}, nil
}

func GetService() (*Service, bool) {
	return instance, instance != nil
}

func (s *Service) GetAuditLog(ctx context.Context, opt *QueryNaviAuditLogOpt) ([]*Resp, error) {
	esCli, err := s.esCli.Get()
	if err != nil {
		return nil, err
	}

	searchService := esCli.Search(fmt.Sprintf("%s*", s.indexPrefix)).
		Sort(timeStampKey, opt.Asc).Sort("_id", opt.Asc).Size(opt.Limit)

	var queries []elastic.Query
	if opt.StartTimestamp > 0 && opt.EndTimestamp >= opt.StartTimestamp {
		queries = append(queries, elastic.NewRangeQuery(timeStampKey).
			Gte(opt.StartTimestamp).
			Lte(opt.EndTimestamp))
	}

	for k, v := range opt.Filter {
		if k != "" && v != "" {
			if k == "Verb" {
				if opt.Lang == "zh" {
					queries = append(queries, elastic.NewMatchQuery(k, v))
				} else {
					queryKey := fmt.Sprintf("MetaData.%s.verb", opt.Lang)
					queries = append(queries, elastic.NewMatchQuery(queryKey, v))
				}
				continue
			}
			if k == "User.Name" {
				queries = append(queries, elastic.NewWildcardQuery(k+".keyword", fmt.Sprintf("*%s*", v)))
				continue
			}
			if k == "Status" {
				queries = append(queries, elastic.NewTermQuery(k, v))
				continue
			}
			queries = append(queries, elastic.NewWildcardQuery(k, fmt.Sprintf("*%s*", v)))
		}
	}

	if len(queries) > 0 {
		searchService = searchService.Query(elastic.NewBoolQuery().Must(queries...))
	}

	if opt.OffsetID != "" {
		record, err := s.GetRecordByID(ctx, opt.OffsetID)
		if err == nil {
			searchService = searchService.SearchAfter(record.Timestamp, opt.OffsetID)
		} else if err != ErrESDocumentNotFound {
			return nil, err
		}
	}

	searchResult, err := searchService.Do(ctx)
	if err != nil {
		return nil, err
	}

	var result = make([]*Resp, 0, len(searchResult.Hits.Hits))
	for _, item := range searchResult.Hits.Hits {
		record, err := parseRecord(item)
		if err != nil {
			logging.Get().Err(err).Msg("parse k8s audit log fail")
			continue
		}
		r := &Resp{
			ID:        item.Id,
			Time:      record.Timestamp,
			UserName:  record.User.Name,
			Ip:        record.HttpRequest.RemoteIP,
			Operation: record.Verb,
			Detail:    record.Detail,
			Status:    record.Status,
			Err:       record.Err,
		}
		if opt.Lang == "zh" {
			r.Operation = record.Verb
			r.Detail = record.Detail
			r.Status = record.Status
		} else {
			data, ok := record.MetaData[opt.Lang]
			if ok {
				eninfo := data.(map[string]interface{})
				r.Operation = eninfo["verb"].(string)
				r.Detail = eninfo["detail"].(string)
				r.Status = eninfo["status"].(string)
			}
		}
		result = append(result, r)
	}

	return result, nil
}

func (s *Service) GetRecordByID(ctx context.Context, id string) (*model.NaviAuditEvent, error) {
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

func parseRecord(item *elastic.SearchHit) (*model.NaviAuditEvent, error) {
	var record model.NaviAuditEvent
	var err = json.Unmarshal(item.Source, &record)
	return &record, err
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

func (s *Service) SendLog(data []byte) error {
	return s.syslogHandler.Log(data)
}

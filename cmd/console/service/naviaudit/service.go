package naviaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	pkgelastic "gitlab.com/security-rd/go-pkg/elastic"
	"gitlab.com/security-rd/go-pkg/logging"
)

const timeStampKey = "Timestamp"

var (
	instance              *Service
	rlOnce                sync.Once
	ErrESDocumentNotFound = errors.New("es document not found")
)

type Service struct {
	esCli       *pkgelastic.ESClient
	indexPrefix string
}

type QueryNaviAuditLogOpt struct {
	OffsetID       string
	Filter         map[string]string
	StartTimestamp int64
	EndTimestamp   int64
	Limit          int
	Asc            bool
}

type Resp struct {
	ID        string
	Time      int64
	UserName  string
	Ip        string
	Operation string
	Detail    string
}

func InitService(ecCli *pkgelastic.ESClient) error {
	rlOnce.Do(func() {
		instance = newService(ecCli)
	})
	return nil
}

func newService(client *pkgelastic.ESClient) *Service {
	return &Service{esCli: client, indexPrefix: "navi-audit-"}
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
				queries = append(queries, elastic.NewMatchQuery(k, v))
				continue
			}
			if k == "User.Name" {
				queries = append(queries, elastic.NewWildcardQuery(k+".keyword", fmt.Sprintf("*%s*", v)))
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
		result = append(result, &Resp{
			ID:        item.Id,
			Time:      record.Timestamp,
			UserName:  record.User.Name,
			Ip:        record.HttpRequest.RemoteIP,
			Operation: record.Verb,
			Detail:    record.Detail,
		})
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

package dal

import (
	"context"
	"errors"

	json "github.com/json-iterator/go"
	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gorm.io/gorm"
)

func SaveProcessingAction(ctx context.Context, db *gorm.DB, action *model.ProcessingAction) error {
	return db.WithContext(ctx).Create(action).Error
}

func GetProcessingActions(ctx context.Context, db *gorm.DB, recordID string) ([]*model.ProcessingAction, error) {
	var actions []*model.ProcessingAction
	var err = db.WithContext(ctx).Where("record_id = ?", recordID).Order("created_at desc").Find(&actions).Error
	return actions, err
}

func SaveProcessingRecord(ctx context.Context, esCli *elastic.Client, index string, record *model.ProcessingRecord) error {
	_, err := esCli.Index().Index(index).Id(record.ID).BodyJson(record).Refresh("true").Do(ctx)
	return err
}

func UpdateProcessingRecord(ctx context.Context, esCli *elastic.Client, index string, change *model.ProcessingRecordChange) error {
	const script = `ctx._source.updatedAt = params.updatedAt; 
					ctx._source.status = params.status; 
					ctx._source.lastOpUser = params.lastOpUser`
	_, err := esCli.UpdateByQuery().Index(index).
		Query(elastic.NewTermQuery("_id", change.ID)).
		Script(elastic.NewScript(script).
			Param("updatedAt", change.UpdatedAt).
			Param("status", change.Status).
			Param("lastOpUser", change.LastOpUser)).
		Refresh("true").Do(ctx)
	return err
}

var (
	ErrNotFound = errors.New("record not found")
)

func QueryProcessingRecordByID(ctx context.Context, esCli *elastic.Client, index, id string) (*model.ProcessingRecord, error) {
	rsp, err := esCli.Search(index).Query(elastic.NewTermQuery("_id", id)).Do(ctx)
	if err != nil {
		return nil, err
	}

	if rsp.Hits == nil || len(rsp.Hits.Hits) != 1 {
		return nil, ErrNotFound
	}

	var record model.ProcessingRecord
	err = json.Unmarshal(rsp.Hits.Hits[0].Source, &record)
	if err != nil {
		return nil, err
	}

	record.ID = id
	return &record, nil
}

func QueryProcessingRecord(ctx context.Context, esCli *elastic.Client, index string, arg *model.QueryProcessingRecordArg) (int64, []*model.ProcessingRecord, error) {
	var queries []elastic.Query
	if arg.StartTimestamp > 0 && arg.EndTimestamp >= arg.StartTimestamp {
		queries = append(queries, elastic.NewRangeQuery("updatedAt").
			Gte(arg.StartTimestamp).Lte(arg.EndTimestamp))
	}
	for k, v := range arg.Filter {
		if k != "" && v != "" {
			queries = append(queries, elastic.NewMatchQuery(k, v))
		}
	}

	total, err := esCli.Count(index).Query(elastic.NewBoolQuery().Must(queries...)).Do(ctx)
	if err != nil {
		return 0, nil, err
	}

	rsp, err := esCli.Search(index).Sort("updatedAt", false).
		Query(elastic.NewBoolQuery().Must(queries...)).
		Size(arg.Limit).
		From(arg.Offset).Do(ctx)
	if err != nil {
		return 0, nil, err
	}

	var records = make([]*model.ProcessingRecord, 0, len(rsp.Hits.Hits))
	for _, item := range rsp.Hits.Hits {
		var record model.ProcessingRecord
		err = json.Unmarshal(item.Source, &record)
		if err != nil {
			return 0, nil, err
		}
		record.ID = item.Id
		records = append(records, &record)
	}

	return total, records, nil
}

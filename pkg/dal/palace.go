package dal

import (
	"context"
	"strconv"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func UpsertAssociatedGraphEvent(ctx context.Context, rdb *gorm.DB, e *model.PalaceAssociatedGraphEvent) (int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()
	err := util.RetryWithBackoff(tctx, func() error {
		oneCtx, cancel := context.WithTimeout(tctx, 500*time.Millisecond)
		defer cancel()
		return rdb.WithContext(oneCtx).Model(e).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "id"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"nodes_num":  e.NodesNum,
				"events_num": e.EventsNum,
				"updated_at": e.UpdatedAt,
				"severity":   gorm.Expr("GREATEST(palace_assoc_graph_events.severity, excluded.severity)"), // TODO FIXIME special grammar for Postgres. take care for MySQL
			}),
		}).Create(e).Error
	})
	if err != nil {
		return 0, err
	}
	return e.ID, nil
}

type SortOption struct {
	columns   []string
	sortOrder string
}

func Sort() *SortOption {
	return new(SortOption)
}
func (o *SortOption) With(cols ...string) *SortOption {
	o.columns = append(o.columns, cols...)
	return o
}
func (o *SortOption) Order(isDesc bool) *SortOption {
	if isDesc {
		o.sortOrder = "desc"
	} else {
		o.sortOrder = "asc"
	}
	return o
}

func (o *SortOption) Ok() bool {
	return len(o.columns) > 0
}
func (o *SortOption) String() string {
	if !o.Ok() {
		return ""
	}
	sb := strings.Builder{}
	for i, col := range o.columns {
		sb.WriteString(col)
		if i < len(o.columns)-1 {
			sb.WriteRune(',')
		}
	}
	if o.sortOrder == "asc" || o.sortOrder == "desc" {
		sb.WriteRune(' ')
		sb.WriteString(o.sortOrder)
	}
	return sb.String()
}

func GetAssociatedGraphEvents(ctx context.Context, rdb *gorm.DB, offsetID int64, limit int) ([]*model.PalaceAssociatedGraphEvent, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	db := rdb.WithContext(tctx).Model(&model.PalaceAssociatedGraphEvent{})
	db = db.Order("id DESC")
	if limit > 0 {
		db = db.Limit(limit)
	}
	if offsetID > 0 {
		db = db.Where("id < ?", offsetID)
	}

	events := make([]*model.PalaceAssociatedGraphEvent, 0, limit)
	err := db.Find(&events).Error
	return events, err
}

func CountAssociatedGraphEvents(ctx context.Context, rdb *gorm.DB) (int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()

	db := rdb.WithContext(tctx).Model(&model.PalaceAssociatedGraphEvent{})
	var count int64
	err := db.Count(&count).Error
	return count, err
}

func GetAssociationLinksOfEvent(ctx context.Context, rdb *gorm.DB, eventID int64) ([]*model.PalaceAssociationLink, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	links := make([]*model.PalaceAssociationLink, 0, 20)
	err := rdb.WithContext(tctx).Model(&model.PalaceAssociationLink{}).Where("aggr_evt_id = ?", eventID).Find(&links).Error
	return links, err
}

type SignalsQuery struct {
	aggrKeys []string
}

func NewSignalsQuery() *SignalsQuery {
	return &SignalsQuery{
		aggrKeys: make([]string, 0),
	}
}
func (q *SignalsQuery) WithAggrKeys(keys []string) *SignalsQuery {
	q.aggrKeys = keys
	return q
}

func GetOriginSignalsOfEvent(ctx context.Context, rdb *gorm.DB, eventID int64, query *SignalsQuery, offsetTime time.Time, limit int) ([]*model.PalaceEventSignalAssociation, error) {
	tctx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()

	db := rdb.WithContext(tctx).Model(&model.PalaceEventSignalAssociation{}).Where("aggr_evt_id = ?", eventID)
	if query.aggrKeys != nil {
		db = db.Where("aggr_key IN ?", query.aggrKeys)
	}
	if limit > 0 {
		db = db.Limit(limit)
	}
	if !offsetTime.IsZero() {
		db = db.Where("created_at < ?", offsetTime)
	} else {
		db = db.Offset(0)
	}
	signals := make([]*model.PalaceEventSignalAssociation, 0, limit)
	err := db.Order("created_at DESC").Find(&signals).Error
	return signals, err
}

func GetSignals(ctx context.Context, esCli *elastic.Client, signalUuids []string) ([]*model.Signal, error) {
	queries := make([]elastic.Query, 0, len(signalUuids))
	for _, signalUuid := range signalUuids {
		uuidInt, err := strconv.ParseInt(signalUuid, 10, 64)
		if err == nil {
			queries = append(queries, elastic.NewMatchQuery("uuid", uuidInt))

		}
	}
	searchSvc := esCli.Search("signal_*").Sort("timestamp", false)
	searchSvc.Query(elastic.NewBoolQuery().Should(queries...).MinimumNumberShouldMatch(1))

	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := searchSvc.Do(tctx)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("query ES error for signalUUIDs %v", signalUuids)
		return nil, err
	}
	signals := make([]*model.Signal, 0, len(result.Hits.Hits))
	for _, item := range result.Hits.Hits {
		var signal model.Signal
		err := json.Unmarshal(item.Source, &signal)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("decode doc error. doc: %s", item.Source)
		} else {
			signals = append(signals, &signal)
		}
	}
	return signals, nil
}

func CountSignalsOfEvent(ctx context.Context, rdb *gorm.DB, eventID int64, query *SignalsQuery) (int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	db := rdb.WithContext(tctx).Model(&model.PalaceEventSignalAssociation{}).Where("aggr_evt_id = ?", eventID)
	if query.aggrKeys != nil {
		db = db.Where("aggr_key IN ?", query.aggrKeys)
	}
	var count int64
	err := db.Count(&count).Error
	return count, err
}

func CreateSignalAssociation(ctx context.Context, rdb *gorm.DB, a *model.PalaceEventSignalAssociation) (int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	a.UUID = util.GenerateUUID64Signed(
		strconv.FormatInt(a.AggrEvtID, 10),
		a.AggrKey,
		a.SignalID,
	)
	err := rdb.WithContext(tctx).Model(a).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uuid"}},
		DoNothing: true,
	}).Create(a).Error
	if err != nil {
		return 0, err
	}
	return a.UUID, nil
}

func CreateAssociationLinks(ctx context.Context, rdb *gorm.DB, l *model.PalaceAssociationLink) (int64, error) {
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	l.UUID = util.GenerateUUID64Signed(
		strconv.FormatInt(l.AggrEvtID, 10),
		l.SrcClusterKey,
		l.SrcLocType,
		l.SrcLocExpr,
		l.DestClusterKey,
		l.DestLocType,
		l.DestLocExpr,
	)
	err := rdb.WithContext(tctx).Model(l).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uuid"}},
		DoNothing: true,
	}).Create(l).Error
	if err != nil {
		return 0, err
	}
	return l.UUID, nil
}

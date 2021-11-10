package reporter

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/datatypes"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type AssociationEvent struct {
	ID              int32          `gorm:"column:id"`
	AssociationType string         `gorm:"column:association_type"`
	RuleModule      string         `gorm:"column:rule_module"`
	RuleCategory    string         `gorm:"column:rule_category"`
	RuleName        string         `gorm:"column:rule_name"`
	Content         datatypes.JSON `gorm:"column:content"`
	Severity        uint8          `gorm:"column:severity"`
	CreatedAt       time.Time      `gorm:"column:created_at"`
	UpdatedAt       time.Time      `gorm:"column:updated_at"`
}

func (AssociationEvent) TableName() string {
	return "association_events"
}

const (
	TimeWindowAssociation = "timeWindow"
)

type TimeWindowEvent struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	NodeType  string `json:"nodeType"`
	NodeKey   string `json:"nodeKey"`
}

const (
	eventBatchSize     = 500
	eventInterval      = time.Second
	eventSeverityPivot = 7
)

func LoadEventsReport(ctx context.Context, db *rdbtools.GormWrapper, startTimestamp, endTimestamp int64, clusterHash map[string]string) *model.EventsReport {
	var result = &model.EventsReport{}
	var offsetID = int32(math.MaxInt32)
	var offsetTime = util.GetTimeByMillisecondTimestamp(endTimestamp)
	var startTime = util.GetTimeByMillisecondTimestamp(startTimestamp)
	for {
		var events []*AssociationEvent
		get := func() error {
			oneCtx, cancel := context.WithTimeout(ctx, time.Second*30)
			defer cancel()
			return db.Get().WithContext(oneCtx).Where("severity >= ? and updated_at >= ? and updated_at < ? and id < ?",
				eventSeverityPivot, startTime, offsetTime, offsetID).
				Order("updated_at desc, id desc").Limit(eventBatchSize).Find(&events).Error
		}

		var err = util.RetryWithBackoff(ctx, get)
		if err != nil {
			logrus.Errorf("load events fail, err:%s", err)
			break
		}

		if len(events) == 0 {
			break
		}

		offsetID = events[len(events)-1].ID
		offsetTime = events[len(events)-1].UpdatedAt

		for _, event := range events {
			if event.AssociationType != TimeWindowAssociation {
				logrus.Errorf("unexpected event type:%s", event.AssociationType)
				continue
			}

			var detail TimeWindowEvent
			err = json.Unmarshal(event.Content, &detail)
			if err != nil {
				logrus.Errorf("parse TimeWindowEvent fail, err:%s", err)
				continue
			}

			if _, ok := clusterHash[detail.Cluster]; !ok {
				continue
			}

			result.Events = append(result.Events, &model.EventItem{
				Cluster:      clusterHash[detail.Cluster],
				Namespace:    detail.Namespace,
				NodeKey:      detail.NodeKey,
				Severity:     event.Severity,
				RuleCategory: event.RuleCategory,
				RuleName:     event.RuleName,
				Timestamp:    util.GetMillisecondTimestampByTime(event.UpdatedAt),
			})
		}

		if len(events) < eventBatchSize {
			break
		}

		time.Sleep(eventInterval)
	}

	return result
}

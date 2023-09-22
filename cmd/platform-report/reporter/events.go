package reporter

import (
	"context"
	"fmt"
	"github.com/olivere/elastic/v7"
	"gitlab.com/security-rd/go-pkg/translate"
	"math"
	"time"

	json "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/datatypes"
	"gorm.io/gorm"
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
	return "ivan_eventcenter_association_events"
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

func LoadEventsReport(ctx context.Context, db *gorm.DB, startTimestamp, endTimestamp int64, clusterHash map[string]string) *model.EventsReport {
	var result = &model.EventsReport{}
	var offsetID = int32(math.MaxInt32)
	var offsetTime = util.GetTimeByMillisecondTimestamp(endTimestamp)
	var startTime = util.GetTimeByMillisecondTimestamp(startTimestamp)
	for {
		var events []*AssociationEvent
		get := func() error {
			oneCtx, cancel := context.WithTimeout(ctx, time.Second*30)
			defer cancel()
			return db.WithContext(oneCtx).Where("severity >= ? and updated_at >= ? and updated_at < ? and id < ?",
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

type RuleKey struct {
	Version1 uint16 `json:"version1"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

type Scope struct {
	Kind string `json:"kind"` // required
	ID   string `json:"id"`   // optional，视具体情况
	Name string `json:"name"` // required
}

type Event struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`         // 事件类型（关联类型）
	Description  string                 `json:"description"`  // 事件描述
	RuleKeys     []RuleKey              `json:"ruleKeys"`     // 该event涉及到的signals，触发的rule列表，去重
	Scopes       map[string][]Scope     `json:"scopes"`       // 关联后，需要保留每个signal的scope，去重
	Resources    []map[string]Scope     `json:"resources"`    // 资源列表，关联信号的所有scope，保留了scope内部的关系，去重
	Relation     map[string]interface{} `json:"relation"`     // 事件的关联表达，可能是图、时间轴
	Severity     int                    `json:"severity"`     // 严重程度 枚举；算法见下方
	Tags         []string               `json:"tags"`         // 事件标签，一期只有系统生成(规则子标签)，二期用户可自定义(标签系统)
	SignalsCount map[int]int            `json:"signalsCount"` // 关联的信号数量，按严重程度拆分
	Context      map[string]interface{} `json:"context"`
	UpdatedAt    int64                  `json:"updatedAt"` // 更新时间
	CreatedAt    int64                  `json:"createdAt"` // 创建时间
	Timestamp    time.Time              `json:"timestamp"`
}

func LoadEventsReportFromES(ctx context.Context, db *gorm.DB, es *elastic.Client, translation *translate.Translation, startTimestamp, endTimestamp int64, lang string) *model.EventsReport {
	var result = &model.EventsReport{}
	boolQuery := elastic.NewBoolQuery()
	//termsQuery := elastic.NewTermsQuery("severity", []interface{}{0, 1, 2, 3}...)
	//boolQuery.Filter(termsQuery)
	rangeQuery := elastic.NewRangeQuery("updatedAt").Gte(startTimestamp).Lte(endTimestamp)
	boolQuery.Filter(rangeQuery)
	boolQuery.Filter(elastic.NewBoolQuery().MustNot(elastic.NewPrefixQuery("ruleKeys.path", "kubeMonitor")))
	res, err := es.Search("events*").Query(boolQuery).Sort("updatedAt", false).From(0).Size(10000).Do(ctx)
	if err != nil {
		logrus.Errorf("search events fail, err:%s", err)
		return result
	}

	if len(res.Hits.Hits) == 0 {
		return result
	}

	rules := make([]model.EvtCenterRule, 0)
	err = db.Find(&rules, "status = 0").Error
	if err != nil {
		logrus.Errorf("find rules fail, err:%s", err)
		return result
	}
	rulesMap := make(map[string]model.EvtCenterRule)
	for i := range rules {
		rulesMap[rules[i].Category+"$"+rules[i].Name] = rules[i]
	}

	countHigh := 0
	countMedium := 0
	countLow := 0
	for _, hit := range res.Hits.Hits {
		e := Event{}
		if err = json.Unmarshal(hit.Source, &e); err != nil {
			logrus.Errorf("unmarshal event fail, err:%s", err)
			continue
		}

		clusterResult := ""
		clusters, ok := e.Scopes["cluster"]
		if ok && len(clusters) != 0 {
			for i := range clusters {
				clusterResult += clusters[i].Name + "、"
			}
			clusterResult = clusterResult[:len(clusterResult)-3]
		}

		namespaceResult := ""
		namespaces, ok := e.Scopes["namespace"]
		if ok && len(namespaces) != 0 {
			for i := range namespaces {
				namespaceResult += namespaces[i].Name + "、"
			}
			namespaceResult = namespaceResult[:len(namespaceResult)-3]
		}

		hostnameResult := ""
		hostnames, ok := e.Scopes["hostname"]
		if ok && len(hostnames) != 0 {
			for i := range hostnames {
				hostnameResult += hostnames[i].Name + "、"
			}
			hostnameResult = hostnameResult[:len(hostnameResult)-3]
		}

		if len(e.RuleKeys) == 0 {
			continue
		}
		rule, ok := rulesMap[e.RuleKeys[0].Category+"$"+e.RuleKeys[0].Name]
		if !ok {
			continue
		}

		contextString := ""
		nContext := translation.Translate(translate.DomainSignalContext, e.Context, lang)
		for k, v := range nContext {
			contextString += fmt.Sprintf("%s: %v<br />", k, v)
		}
		if len(contextString) != 0 {
			contextString = contextString[:len(contextString)-1]
		}

		resolution := ""
		for i := range rule.CustomKV {
			for k, v := range rule.CustomKV[i].KVHash {
				if k == "en" && v.Key == "Suggestions" && lang == "en" {
					resolution = v.Value
				} else if k == "zh" && v.Key == "处置建议" && lang == "zh" {
					resolution = v.Value
				}
			}
		}

		result.Events = append(result.Events, &model.EventItem{
			Cluster:         clusterResult,
			Namespace:       namespaceResult,
			NodeKey:         hostnameResult,
			Severity:        uint8(e.Severity),
			RuleCategory:    translation.One(translate.DomainRuleKey, translate.KeyCategory, rule.Category, lang),
			RuleName:        translation.One(translate.HolaKey(e.RuleKeys[0].Version1, translate.DomainRuleKey), translate.KeyName, rule.Name, lang),
			RuleDescription: translation.One(translate.HolaKey(e.RuleKeys[0].Version1, translate.DomainRuleEvent), translate.KeyDescription, rule.Description, lang),
			Resolution:      resolution,
			Context:         contextString,
			Timestamp:       e.UpdatedAt,
		})

		if e.Severity >= 0 && e.Severity <= 3 {
			countHigh++
		} else if e.Severity >= 4 && e.Severity <= 5 {
			countMedium++
		} else {
			countLow++
		}
	}

	result.Count = map[string]int{
		"high":   countHigh,
		"medium": countMedium,
		"low":    countLow,
	}

	return result
}

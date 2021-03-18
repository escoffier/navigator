package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/olivere/elastic/v7"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	rcache "gitlab.com/piccolo_su/vegeta/pkg/cache"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	r "gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	alertPollInterval = time.Second * 30
	alertPollTimeout  = time.Second * 15
	cacheWriteTTLSec  = 24 * 60 * 60
	cacheReadTTLSec   = 60 * 60
)

type AlertService struct {
	elasticIndex      string
	elasticClient     *elastic.Client
	rs                *rule.RuleService
	mongodb           *mongo.Database
	lastPollTimestamp time.Time
	alertsCache       *rcache.AlertsCache
	ctx               context.Context
}

func NewAlertService(ctx context.Context, redisClient *redis.Client, rs *rule.RuleService, es *elastic.Client, elasticIndex string, mongodb *mongo.Database) *AlertService {
	alertService := &AlertService{
		elasticIndex:      elasticIndex,
		elasticClient:     es,
		rs:                rs,
		mongodb:           mongodb,
		lastPollTimestamp: time.Now(),
		alertsCache:       rcache.NewAlertsCache(ctx, mongodb, redisClient),
		ctx:               ctx,
	}
	go alertService.elasticsearchAlertPoller()
	return alertService
}

func (s *AlertService) elasticsearchAlertPoller() {
	logging.GetLogger().Info().Msg("Started image scan alert poller")

	var wg sync.WaitGroup
	defer wg.Done()
	wg.Add(1)
	ticker := time.NewTicker(alertPollInterval)
	elastAlertCleanup, err := s.elasticClient.BulkProcessor().
		Name("ElastAlert cleaner").
		Workers(2).
		BulkActions(1000).
		BulkSize(5 << 20).
		FlushInterval(30 * time.Second).
		Stats(true).
		Do(s.ctx)
	if err != nil {
		logging.GetLogger().Error().Err(NewAnError(http.StatusInternalServerError, fmt.Errorf("Could not start elastalert cleanup: %w", err)))
	}
	defer elastAlertCleanup.Close()

	aggrCache := NewAlertAggrCache(10, cacheReadTTLSec, cacheWriteTTLSec)

loop:
	for {
		select {
		case <-ticker.C:
			pollCtx, pollCtxCancel := context.WithTimeout(s.ctx, alertPollTimeout)
			defer pollCtxCancel()
			err := s.pollRuntimeDetectionAlerts(pollCtx, elastAlertCleanup, aggrCache)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Error when polling image scan alerts")
			}
		case <-s.ctx.Done():
			break loop
		}
	}
	logging.GetLogger().Info().Msg("Shutting down image scan alert poller")
}

func isAlertContextAlmostTheSame(newCtx model.AlertContext, oldCtx model.AlertContext) bool {
	if newCtx.ElasticID == oldCtx.ElasticID {
		return true
	}
	if newCtx.ContainerID == oldCtx.ContainerID && newCtx.PodUID == newCtx.PodUID {
		delta := (newCtx.Timestamp.Unix() - oldCtx.Timestamp.Unix())
		return delta > -60 && delta < 60
	}
	return false
}

func (s *AlertService) pollRuntimeDetectionAlerts(ctx context.Context, elastAlertCleanup *elastic.BulkProcessor, aggrCache *AlertAggrCache) error {
	lastPollTimestampFrom := s.lastPollTimestamp.Add(time.Duration(-5) * time.Minute)
	lastPollTimestampTo := time.Now()
	defer func() {
		s.lastPollTimestamp = lastPollTimestampTo
	}()

	var buf bytes.Buffer
	query := fmt.Sprintf(
		`{
			"query": {
				"range": {
					"@timestamp": {
						"gte": "%s",
						"lt": "%s"
					}
				}
			},
			"size": 5000
		}`, lastPollTimestampFrom.Format(time.RFC3339), lastPollTimestampTo.Format(time.RFC3339))

	var b strings.Builder
	b.WriteString(query)
	read := strings.NewReader(b.String())

	if err := json.NewEncoder(&buf).Encode(read); err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to marshal elasticsearch query: %w", err))
	}
	if s.elasticClient == nil {
		return NewElasticError(http.StatusInternalServerError, fmt.Errorf("elasticsearch client is nil"))
	}
	searchResult, err := s.elasticClient.Search().
		Index(s.elasticIndex).
		Source(query).
		Pretty(true).
		Do(ctx)
	if err != nil {
		return NewElasticError(http.StatusInternalServerError, fmt.Errorf("Failed to get elasticsearch results: %w", err))
	}

	rules, _, err := s.rs.ListRules(ctx, 0, 500)
	if err != nil {
		return fmt.Errorf("Failed to get platform detection rules: %w", err)
	}
	enabledRules := make([]model.Rule, 0)
	for _, rule := range rules {
		if rule.Enabled {
			enabledRules = append(enabledRules, rule)
		}
	}

	if searchResult.Hits.TotalHits.Value == 0 {
		return nil
	}

	logging.GetLogger().Info().Int("hits", len(searchResult.Hits.Hits)).Msg("Found alert entries in ES")

	for _, hit := range searchResult.Hits.Hits {
		elasticID := hit.Id

		deleteRequest := elastic.NewBulkDeleteRequest().
			Index(s.elasticIndex).
			Id(elasticID)
		elastAlertCleanup.Add(deleteRequest)

		var elasticAlert map[string]interface{}
		err := json.Unmarshal(hit.Source, &elasticAlert)
		if err != nil {
			return NewElasticError(http.StatusInternalServerError,
				fmt.Errorf("Failed to parse elasticsearch result: %w", err),
				Suberror{"elasticID", elasticID})
		}
		logging.GetLogger().Debug().Str("elastalert", fmt.Sprintf("%+v", elasticAlert)).Msg("Analysing alert entry")

		vulnerability := ""
		if val, ok := elasticAlert["socket__protocol"]; ok {
			if int(val.(float64)) == 132 {
				vulnerability = "CVE-2019-3874"
			}
		}
		if val, ok := elasticAlert["socket__family"]; ok {
			if int(val.(float64)) == 17 {
				vulnerability = "CVE-2020-14386"
			}
		}
		if _, ok := elasticAlert["reverse_shell_socket_dup2"]; ok {
			vulnerability = "RS-SOCKET_DUP2"
		}
		if _, ok := elasticAlert["openat__filename"]; ok {
			vulnerability = "CVE-2019-5736"
		}
		if _, ok := elasticAlert["open__filename"]; ok {
			vulnerability = "CVE-2019-5736"
		}
		if val, ok := elasticAlert["execve__filename"]; ok {
			if val.(string) == "/usr/bin/sudo" {
				vulnerability = "CVE-2019-14287"
			} else if val.(string) == "/bin/nc" || val.(string) == "/usr/bin/ncat" {
				vulnerability = "RS-NC"
			}
		}
		if val, ok := elasticAlert["exec__filename"]; ok {
			if val.(string) == "/usr/bin/sudo" {
				vulnerability = "CVE-2019-14287"
			} else if val.(string) == "/bin/nc" || val.(string) == "/usr/bin/ncat" {
				vulnerability = "RS-NC"
			}
		}

		logging.GetLogger().Info().Str("elasticID", elasticID).Str("vulnerability", vulnerability).Msg("Checking if vulnerability supported")

		timestamp, err := time.Parse(time.RFC3339, elasticAlert["@timestamp"].(string))
		if err != nil {
			return NewElasticError(http.StatusInternalServerError,
				fmt.Errorf("Failed to parse timestamp as RFC3339: %w", err),
				Suberror{"elasticID", elasticID},
				Suberror{"timestamp", elasticAlert["@timestamp"].(string)})
		}
		alertCtx := model.AlertContext{
			ElasticID:   elasticID,
			ContainerID: elasticAlert["ContainerID"].(string),
			PodName:     elasticAlert["PodName"].(string),
			PodUID:      elasticAlert["PodUID"].(string),
			Timestamp:   timestamp.Local(), // use local time; should do it in frontend; FIXME
		}

		numRaised := 0

		var enabledRule *model.Rule
		for _, rule := range enabledRules {
			if rule.NameEn == vulnerability {
				enabledRule = &rule
				break
			}
		}

		if enabledRule == nil {
			logging.GetLogger().Info().
				Msg("Didn't raise any alert to mongo, because no matched vulnerability was enabled")
			return nil
		}

		logging.GetLogger().Info().Str("elasticID", elasticID).Str("vulnerability", vulnerability).Msg("Vulnerability supported")

		podUID := elasticAlert["PodUID"].(string)
		podName := elasticAlert["PodName"].(string)
		cluster := "default"
		var services []string
		var namespace string
		var svcOK bool
		saService, saOk := assetsSvc.GetServiceAssetsService()
		if saOk && saService.IsClusterSynced(cluster) {
			svcs, ns, ok := saService.GetServiceInfoOfPod(cluster, podUID)
			if ok {
				services = svcs
				namespace = ns
				svcOK = true
			}
		}
		if !svcOK {
			services = []string{"unknown"}
			namespace = "unknown"
		}

		for _, service := range services {
			aggrKey := fmt.Sprintf("%s:%s:%s:%s", cluster, namespace, service, vulnerability) // cached by cluster:namespace:service:vulnerability_rule
			idPtr, cacheExist := aggrCache.GetByKey(aggrKey, timestamp.Unix())
			var alert *model.Alert
			if cacheExist && idPtr != nil {
				logging.GetLogger().Info().Msgf("alerts aggr cache hits with key: %s and got value: %v", vulnerability, *idPtr)
				filter := bson.M{"_id": *idPtr}

				queryResult := s.mongodb.Collection(model.AlertsCollection.String()).FindOne(ctx, filter)

				if queryResult.Err() == nil {
					alert = new(model.Alert)
					decErr := queryResult.Decode(alert)
					if decErr != nil {
						logging.GetLogger().Err(decErr).Msgf("query alerts collection id %v err", *idPtr)
						alert = nil
					}
				} else {
					logging.GetLogger().Err(queryResult.Err()).Msgf("query alerts collection id %v err", *idPtr)
				}
			}

			if alert != nil { // There are aggregated Alert instance.
				// if this history exists, don't update
				existed := false
				for _, histCtx := range alert.Histories {
					if isAlertContextAlmostTheSame(alertCtx, histCtx) {
						existed = true
						break
					}
				}

				if !existed {
					alert.Timestamp = timestamp
					if strings.HasPrefix(vulnerability, "CVE") {
						if alert.RuntimeDetectionAlert == nil {
							alert.RuntimeDetectionAlert = new(model.RuntimeDetectionAlert)
							alert.RuntimeDetectionAlert.DescriptionEn = enabledRule.DescriptionEn
							alert.RuntimeDetectionAlert.DescriptionZh = enabledRule.DescriptionZh
							alert.RuntimeDetectionAlert.RuleID = enabledRule.ID
							alert.RuntimeDetectionAlert.RuleNameEn = enabledRule.NameEn
							alert.RuntimeDetectionAlert.RuleNameZh = enabledRule.NameZh
							alert.RuntimeDetectionAlert.Cvss2Score = enabledRule.Cvss2Score
							alert.RuntimeDetectionAlert.Cvss2Vector = enabledRule.Cvss2Vector
							alert.RuntimeDetectionAlert.Cvss3Score = enabledRule.Cvss3Score
							alert.RuntimeDetectionAlert.Cvss3Vector = enabledRule.Cvss3Vector
						}
						alert.RuntimeDetectionAlert.ElasticID = elasticID
						alert.RuntimeDetectionAlert.ContainerID = elasticAlert["ContainerID"].(string)
						alert.RuntimeDetectionAlert.PodName = podName
						alert.RuntimeDetectionAlert.PodUID = podUID
					} else {
						if alert.ExploitRiskAlert == nil {
							alert.ExploitRiskAlert = new(model.ExploitRiskAlert)
							alert.ExploitRiskAlert.ElasticID = elasticID

							alert.ExploitRiskAlert.RuleID = enabledRule.ID
							alert.ExploitRiskAlert.DescriptionEn = enabledRule.DescriptionEn
							alert.ExploitRiskAlert.DescriptionZh = enabledRule.DescriptionZh
							alert.ExploitRiskAlert.RuleNameEn = enabledRule.NameEn
							alert.ExploitRiskAlert.RuleNameZh = enabledRule.NameZh
							alert.ExploitRiskAlert.PID = int(elasticAlert["Pid"].(float64))
						}
						alert.ExploitRiskAlert.ContainerID = elasticAlert["ContainerID"].(string)
						alert.ExploitRiskAlert.PodName = podName
						alert.ExploitRiskAlert.PodUID = podUID

					}
					alert.Histories = append(alert.Histories, alertCtx)
					alert.Service = service
					alert.Namespace = namespace
					alert.Cluster = cluster
					filter := bson.M{"_id": *idPtr}
					// delete the previous one and insert into the new one. So the Mongo _id will be updated after merging.
					alert.ID = primitive.NewObjectIDFromTimestamp(time.Now())
					_, err = s.mongodb.Collection(model.AlertsCollection.String()).DeleteOne(ctx, filter)
					if err != nil {
						logging.GetLogger().Err(err).Msgf("Failed to delete alert from elastic to mongo: %w", err)
					}

					_, err = s.mongodb.Collection(model.AlertsCollection.String()).InsertOne(ctx, alert)
					if err != nil {
						return NewMongoError(http.StatusInternalServerError,
							fmt.Errorf("Failed to insert alert from elastic to mongo: %w", err),
							Suberror{"elasticID", elasticID})
					} else {
						earlist := timestamp
						if len(alert.Histories) > 0 {
							earlist = alert.Histories[0].Timestamp
						}
						aggrCache.Put(aggrKey, alert.ID, earlist.Unix(), timestamp.Unix()) // set the previous write timestamp and read timestap
					}
				}
			} else {
				if strings.HasPrefix(vulnerability, "CVE") {
					sev := r.GetSeverityFromScore(int64(enabledRule.Cvss3Score * 10))
					alert = &model.Alert{
						ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
						AlertKind:   string(model.AlertKindRuntimeDetection),
						Severity:    sev,
						SeverityInt: util.SeverityToInt(sev),
						Timestamp:   timestamp,
						MessageEn:   "Potential " + enabledRule.NameEn,
						MessageZh:   "潜在 " + enabledRule.NameZh,
						Active:      true,
						Service:     service,
						Namespace:   namespace,
						Cluster:     cluster,
						RuntimeDetectionAlert: &model.RuntimeDetectionAlert{
							ElasticID:     elasticID,
							ContainerID:   elasticAlert["ContainerID"].(string),
							PodName:       podName,
							PodUID:        podUID,
							DescriptionEn: enabledRule.DescriptionEn,
							DescriptionZh: enabledRule.DescriptionZh,
							RuleID:        enabledRule.ID,
							RuleNameEn:    enabledRule.NameEn,
							RuleNameZh:    enabledRule.NameZh,
							Cvss2Score:    enabledRule.Cvss2Score,
							Cvss2Vector:   enabledRule.Cvss2Vector,
							Cvss3Score:    enabledRule.Cvss3Score,
							Cvss3Vector:   enabledRule.Cvss3Vector,
						},
					}
				} else {
					sev := r.SeverityHigh
					alert = &model.Alert{
						ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
						AlertKind:   string(model.AlertKindExploitRisk),
						Timestamp:   timestamp,
						Severity:    sev,
						SeverityInt: util.SeverityToInt(string(sev)),
						MessageEn:   "Other Runtime ",
						MessageZh:   "潛在利用",
						Active:      true,
						Service:     service,
						Namespace:   namespace,
						Cluster:     cluster,
						ExploitRiskAlert: &model.ExploitRiskAlert{
							ElasticID:     elasticID,
							ContainerID:   elasticAlert["ContainerID"].(string),
							PodName:       podName,
							PodUID:        podUID,
							RuleID:        enabledRule.ID,
							DescriptionEn: enabledRule.DescriptionEn,
							DescriptionZh: enabledRule.DescriptionZh,
							RuleNameEn:    enabledRule.NameEn,
							RuleNameZh:    enabledRule.NameZh,
							PID:           int(elasticAlert["Pid"].(float64)),
						},
					}
				}
				alert.Histories = []model.AlertContext{
					alertCtx,
				}
				now := time.Now()
				alert.HistoricisedTimestamp = now
				_, err = s.mongodb.Collection(model.AlertsCollection.String()).InsertOne(ctx, alert)
				if err != nil {
					return NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Failed to insert alert from elastic to mongo: %w", err),
						Suberror{"elasticID", elasticID})
				} else {
					// put them to cache
					aggrCache.Put(aggrKey, alert.ID, timestamp.Unix(), timestamp.Unix())
				}
			}

		}

		numRaised++

		if numRaised == 0 {

		} else {
			logging.GetLogger().Info().
				Int("numRaised", numRaised).
				Msg("Raised alerts to mongo")
		}
	}

	s.lastPollTimestamp = lastPollTimestampTo
	return nil
}

func (s *AlertService) AcknowledgeAlert(ctx context.Context, alertObjectID primitive.ObjectID) (*model.Alert, error) {
	filter := bson.M{"_id": alertObjectID}
	alertResult := s.mongodb.Collection(model.AlertsCollection.String()).FindOne(ctx, filter)
	if alertResult.Err() != nil {
		if alertResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", alertResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", alertResult.Err()))
	}

	var oldAlert model.Alert
	err := alertResult.Decode(&oldAlert)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", alertResult.Err()))
	}

	if oldAlert.Acknowledged {
		return nil, NewAlertAlreadyAcknowledgedError(http.StatusBadRequest, fmt.Errorf("Alert already acknowledged"))
	}

	update := bson.M{"$set": bson.M{
		"acknowledged":           true,
		"historicised_timestamp": time.Now(),
	}}

	_, err = s.mongodb.Collection(model.AlertsCollection.String()).UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update: %w", err))
	}

	afterUpdateResult := s.mongodb.Collection(model.AlertsCollection.String()).FindOne(ctx, filter)
	if afterUpdateResult.Err() != nil {
		if afterUpdateResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", afterUpdateResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", afterUpdateResult.Err()))
	}

	var updatedAlert model.Alert
	err = afterUpdateResult.Decode(&updatedAlert)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", afterUpdateResult.Err()))
	}

	err = s.alertsCache.RefreshCache()
	if err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't refresh cache: %w", err))
	}

	return &updatedAlert, nil
}

// QuickCheckAlertsUpdates if there are more than 10 updates, it will return updateNum = 11, not a correct actual number.
func (s *AlertService) QuickCheckAlertsUpdates(ctx context.Context, givenCuror string) (cursor string, updateNum int, err error) {
	alertIDs, _, cacheErr := s.alertsCache.GetItems(ctx, model.AlertKindAny, 0, 10, "timestamp", "desc", true)
	if cacheErr != nil {
		logging.GetLogger().Err(cacheErr).Msgf("CheckAlertsUpdate query cache error. given cursor: %s", givenCuror)
		return "", 0, cacheErr
	}
	if len(alertIDs) == 0 {
		if len(givenCuror) == 0 {
			return "", 0, nil
		} else {
			return "", 0, errors.New("no cache found for alerts")
		}
	}
	cursor = alertIDs[0].ID.Hex()
	for i, aid := range alertIDs {
		if aid.ID.Hex() == givenCuror {
			return cursor, i, nil
		}
	}
	return cursor, 10, nil
}

func (s *AlertService) alertCheckHistoriesActive(alert *model.Alert) {
	saService, ok := assetsSvc.GetServiceAssetsService()
	if !ok || saService == nil || !saService.IsClusterSynced(alert.Cluster) {
		return
	}

	newHistories := make([]model.AlertContext, len(alert.Histories))
	for i, history := range alert.Histories {
		_, _, active := saService.GetServiceInfoOfPod(alert.Cluster, history.PodUID)
		newHistories[i] = history
		newHistories[i].Active = active
	}
	alert.Histories = newHistories
}
func (s *AlertService) ListAlerts(ctx context.Context, offset int64, limit int64, kind model.AlertKind, sortBy string, sortOrder string, onlyNotAcknowledged bool) ([]model.Alert, int64, error) {
	alertIds, docNum, err := s.alertsCache.GetItems(ctx, kind, offset, limit, sortBy, sortOrder, onlyNotAcknowledged)
	if err != nil {
		return nil, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Failed to get results from cache: %w", err))
	}

	items := make([]model.Alert, len(alertIds))
	ids := make([]primitive.ObjectID, len(alertIds))
	for i := range alertIds {
		ids[i] = alertIds[i].ID
	}

	filter := bson.D{{"_id", bson.D{{"$in", ids}}}}
	opts := options.Find()
	opts.SetMaxTime(time.Second * 10)
	opts.SetSort(bson.D{{sortBy, util.SortOrderToInt(sortOrder)}})

	coll := s.mongodb.Collection(model.AlertsCollection.String())
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	cur, err := coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find documents: %w", err))
	}
	defer cur.Close(mongoCtx)
	var alertNo int = 0
	for cur.Next(mongoCtx) {
		var alert model.Alert
		err := cur.Decode(&alert)
		if err != nil {
			return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}

		s.alertCheckHistoriesActive(&alert)
		alert.ApplyTranslation(ctx)

		items[alertNo] = alert
		alertNo++
	}
	err = cur.Err()
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Mongo cursor error: %w", err))
	}

	return items, docNum, nil

}

func (s *AlertService) OneNodeAlert(ctx context.Context, nodeName string, action string) (alerts []model.Alert, count int, err error) {
	c, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	coll := s.mongodb.Collection(model.AlertsCollection.String())

	filter := bson.M{
		"runtimeDetectionAlert.containerId": nodeName,
	}

	var cur *mongo.Cursor
	cur, err = coll.Find(c, filter)
	if err != nil {
		return
	}

	switch action {
	case "count":
		for cur.Next(c) {
			var alert model.Alert
			err = cur.Decode(&alert)
			cur.Current.Elements()
			if err != nil {
				return
			} else {
				count++
			}
		}

	default:
		err = errors.New("action error")
		return
	}

	if c.Err() != nil {
		err = c.Err()
		return
	}

	return
}

func (s *AlertService) RefreshCache() error {
	return s.alertsCache.RefreshCache()
}

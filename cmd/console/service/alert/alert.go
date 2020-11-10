package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/olivere/elastic/v7"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	r "gitlab.com/piccolo_su/vegeta/pkg/redclair"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	alertPollInterval = time.Second * 30
	alertPollTimeout  = time.Second * 15
)

type AlertService struct {
	elasticIndex      string
	elasticClient     *elastic.Client
	rs                *rule.RuleService
	mongodb           *mongo.Database
	lastPollTimestamp time.Time
	ctx               context.Context
}

func NewAlertService(ctx context.Context, rs *rule.RuleService, es *elastic.Client, elasticIndex string, mongodb *mongo.Database) *AlertService {
	alertService := &AlertService{
		elasticIndex:      elasticIndex,
		elasticClient:     es,
		rs:                rs,
		mongodb:           mongodb,
		lastPollTimestamp: time.Now(),
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
loop:
	for {
		select {
		case <-ticker.C:
			pollCtx, pollCtxCancel := context.WithTimeout(s.ctx, alertPollTimeout)
			defer pollCtxCancel()
			err := s.pollImageScanAlerts(pollCtx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Error when polling image scan alerts")
			}
		case <-s.ctx.Done():
			break loop
		}
	}
	logging.GetLogger().Info().Msg("Shutting down image scan alert poller")
}

func (s *AlertService) pollImageScanAlerts(ctx context.Context) error {
	lastPollTimestampFrom := s.lastPollTimestamp.Add(time.Duration(-5) * time.Minute)
	lastPollTimestampTo := time.Now()
	defer func() {
		s.lastPollTimestamp = lastPollTimestampTo
	}()

	logging.GetLogger().Info().Str("fromTimestamp", lastPollTimestampFrom.Format(time.RFC3339)).Str("timetsampTo", lastPollTimestampTo.Format(time.RFC3339)).Msg("Searching for new detections")
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
			}
		}`, lastPollTimestampFrom.Format(time.RFC3339), lastPollTimestampTo.Format(time.RFC3339))

	var b strings.Builder
	b.WriteString(query)
	read := strings.NewReader(b.String())

	if err := json.NewEncoder(&buf).Encode(read); err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to marshal elasticsearch query: %w", err))
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
			logging.GetLogger().Info().Str("rule", rule.Name).Msg("Enabled rule")
		}
	}

	if searchResult.Hits.TotalHits.Value == 0 {
		return nil
	}

	for _, hit := range searchResult.Hits.Hits {
		elasticID := hit.Id
		var elasticAlert map[string]interface{}
		err := json.Unmarshal(hit.Source, &elasticAlert)
		if err != nil {
			return NewElasticError(http.StatusInternalServerError,
				fmt.Errorf("Failed to parse elasticsearch result: %w", err),
				Suberror{"elasticID", elasticID})
		}

		filter := bson.M{
			"$or": []bson.M{
				{"imageScanAlert.elasticId": elasticID},
				{"exploitRiskAlert.elasticId": elasticID},
			},
		}
		queryResult := s.mongodb.Collection(model.AlertCollection).FindOne(ctx, filter)

		if queryResult.Err() != nil && queryResult.Err() != mongo.ErrNoDocuments {
			return NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("Failed to check if alert is already recognized by the system: %w", err),
				Suberror{"elasticID", elasticID})
		}

		if queryResult.Err() == nil {
			logging.GetLogger().Info().Str("elasticID", elasticID).Msg("Alert already reported into mongo, skipping")
			continue
		}

		// else queryResult.Err() == mongo.ErrNoDocuments

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
		if val, ok := elasticAlert["openat__filename"]; ok {
			if val.(string) == "/proc/self/exe" {
				vulnerability = "CVE-2019-5736"
			}
		}
		if val, ok := elasticAlert["open__filename"]; ok {
			if val.(string) == "/proc/self/exe" {
				vulnerability = "CVE-2019-5736"
			}
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

		numRaised := 0
		for _, enabledRule := range enabledRules {
			if enabledRule.Name == vulnerability {

				logging.GetLogger().Info().Str("elasticID", elasticID).Str("vulnerability", vulnerability).Msg("Vulnerability supported")

				timestamp, err := time.Parse(time.RFC3339, elasticAlert["@timestamp"].(string))
				if err != nil {
					return NewElasticError(http.StatusInternalServerError,
						fmt.Errorf("Failed to parse timestamp as RFC3339: %w", err),
						Suberror{"elasticID", elasticID},
						Suberror{"timestamp", elasticAlert["@timestamp"].(string)})
				}

				var alert model.Alert
				if strings.HasPrefix(vulnerability, "CVE") {
					alert = model.Alert{
						ID:        primitive.NewObjectIDFromTimestamp(time.Now()),
						AlertKind: model.AlertKindImageScan,
						Severity:  r.GetSeverityFromScore(int64(enabledRule.Cvss3Score*10)),
						Timestamp: timestamp,
						ImageScanAlert: &model.ImageScanAlert{
							ElasticID:   elasticID,
							ContainerID: elasticAlert["ContainerID"].(string),
							PodName:     elasticAlert["PodName"].(string),
							PodUID:      elasticAlert["PodUID"].(string),
							RuleName:    enabledRule.Name,
							Cvss3Score:  enabledRule.Cvss3Score,
							Cvss3Vector: enabledRule.Cvss3Vector,
						},
					}
				} else {
					alert = model.Alert{
						ID:        primitive.NewObjectIDFromTimestamp(time.Now()),
						AlertKind: model.AlertKindExploitRisk,
						Timestamp: timestamp,
						Severity:  r.SeverityHigh,
						ExploitRiskAlert: &model.ExploitRiskAlert{
							ElasticID:   elasticID,
							ContainerID: elasticAlert["ContainerID"].(string),
							PodName:     elasticAlert["PodName"].(string),
							PodUID:      elasticAlert["PodUID"].(string),
							RuleName:    enabledRule.Name,
							PID:         int(elasticAlert["Pid"].(float64)),
						},
					}
				}

				numRaised++

				_, err = s.mongodb.Collection(model.AlertCollection).InsertOne(ctx, alert)
				if err != nil {
					return NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Failed to insert alert from elastic to mongo: %w", err),
						Suberror{"elasticID", elasticID})
				}
			}
		}

		if numRaised == 0 {
			logging.GetLogger().Info().
				Str("elasticID", elasticID).
				Str("vulnerability", vulnerability).
				Msg("Didn't raise any alert to mongo, because no matched vulnerability was enabled")
		} else {
			logging.GetLogger().Info().
				Int("numRaised", numRaised).
				Str("vulnerability", vulnerability).
				Msg("Raised alerts to mongo")
		}
	}

	s.lastPollTimestamp = lastPollTimestampTo
	return nil
}

func (s *AlertService) AcknowledgeAlert(ctx context.Context, alertObjectID primitive.ObjectID) (*model.Alert, error) {
	filter := bson.M{"_id": alertObjectID}
	alertResult := s.mongodb.Collection(model.AlertCollection).FindOne(ctx, filter)
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
		"acknowledged": true,
	}}

	_, err = s.mongodb.Collection(model.AlertCollection).UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update: %w", err))
	}

	afterUpdateResult := s.mongodb.Collection(model.AlertCollection).FindOne(ctx, filter)
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

	return &updatedAlert, nil
}

func (s *AlertService) ListAlerts(ctx context.Context, offset int64, limit int64, onlyNotAcknowledged bool) ([]model.Alert, int64, error) {
	filter := bson.M{}
	if onlyNotAcknowledged {
		filter = bson.M{"acknowledged": false}
	}

	opts := options.Find()
	opts.SetSkip(offset)
	opts.SetLimit(limit)
	opts.SetSort(bson.D{{"timestamp", -1}})
	coll := s.mongodb.Collection(model.AlertCollection)
	cur, err := coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't find documents: %w", err))
	}
	defer cur.Close(ctx)

	var alerts []model.Alert

	for cur.Next(ctx) {
		var alert model.Alert
		err := cur.Decode(&alert)
		if err != nil {
			return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}

		alerts = append(alerts, alert)
	}

	docNum, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't count documents: %w", err))
	}
	return alerts, docNum, err
}

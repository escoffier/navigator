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

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/alert"
	r "gitlab.com/piccolo_su/vegeta/cmd/console/model/rule"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/rule"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	alertCol          = "alert"
	alertPollInterval = time.Second * 30
	alertPollTimeout  = time.Second * 15
)

type AlertService struct {
	elasticIndex      string
	elasticClient     *elastic.Client
	rs                *rule.RuleService
	mongodb           *mongo.Database
	lastPollTimestamp string
	ctx               context.Context
}

func NewAlertService(ctx context.Context, rs *rule.RuleService, es *elastic.Client, elasticIndex string, mongodb *mongo.Database) *AlertService {
	alertService := &AlertService{
		elasticIndex:      elasticIndex,
		elasticClient:     es,
		rs:                rs,
		mongodb:           mongodb,
		lastPollTimestamp: time.Now().Format(time.RFC3339),
		ctx:               ctx,
	}
	go alertService.alertPoller()
	return alertService
}

func (s *AlertService) alertPoller() {
	logging.GetLogger().Info().Msg("Started alert poller")

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
			err := s.pollAlerts(pollCtx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Alert poller error - alert polling failed")
			}
		case <-s.ctx.Done():
			break loop
		}
	}
	logging.GetLogger().Info().Msg("Shutting down Alert poller")
}

func (s *AlertService) pollAlerts(ctx context.Context) error {
	lastPollTimestampFrom := s.lastPollTimestamp
	lastPollTimestampTo := time.Now().Format(time.RFC3339)

	logging.GetLogger().Info().Str("fromTimestamp", lastPollTimestampFrom).Str("timetsampTo", lastPollTimestampTo).Msg("Searching for new detections")
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
		}`, lastPollTimestampFrom, lastPollTimestampTo)

	var b strings.Builder
	b.WriteString(query)
	read := strings.NewReader(b.String())

	if err := json.NewEncoder(&buf).Encode(read); err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to marshal elasticsearch query")
		return err
	}

	searchResult, err := s.elasticClient.Search().
		Index(s.elasticIndex).
		Source(query).
		Pretty(true).
		Do(ctx)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get elasticsearch results")
		return err
	}

	rules, _, err := s.rs.ListRules(ctx, 0, 500)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get platform detection rules")
		return err
	}
	enabledRules := make([]r.Rule, 0)
	for _, rule := range rules {
		if rule.Enabled {
			enabledRules = append(enabledRules, rule)
			logging.GetLogger().Info().Str("rule", rule.Name).Msg("Enabled rule")
		}
	}

	results := make([]alert.Alert, 0)
	if searchResult.Hits.TotalHits.Value > 0 {
		for _, hit := range searchResult.Hits.Hits {
			var queryAlert alert.Alert
			elasticID := hit.Uid
			var elasticAlert map[string]interface{}
			err := json.Unmarshal(hit.Source, &elasticAlert)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to parse elasticsearch result")
			}
			filter := bson.M{"elasticId": elasticID}
			queryResult := s.mongodb.Collection(alertCol).FindOne(ctx, filter)
			if queryResult.Err() != nil {
				if queryResult.Err() == mongo.ErrNoDocuments {
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
						vulnerability = "RS_SOCKET_DUP2"
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

					logging.GetLogger().Info().Str("vulnerability", vulnerability).Msg("Checking if vulnerability supported")
					for _, enabledRule := range enabledRules {
						if enabledRule.Name == vulnerability {
							logging.GetLogger().Info().Str("vulnerability", vulnerability).Msg("Vulnerability supported")

							queryAlert.ID = primitive.NewObjectIDFromTimestamp(time.Now())
							queryAlert.Acknowledged = false
							queryAlert.ContainerID = elasticAlert["ContainerID"].(string)
							queryAlert.ElasticID = elasticID
							queryAlert.PodName = elasticAlert["PodName"].(string)
							queryAlert.PodUID = elasticAlert["PodUID"].(string)
							queryAlert.RuleName = enabledRule.Name
							queryAlert.Cvss3Score = enabledRule.Cvss3Score
							queryAlert.Cvss3Vector = enabledRule.Cvss3Vector
							elasticTimestampLayout := "2006-01-02T15:04:05.000Z"
							t, err := time.Parse(elasticTimestampLayout, elasticAlert["@timestamp"].(string))
							if err != nil {
								logging.GetLogger().Error().Err(err).Str("timestamp", elasticAlert["@timestamp"].(string)).Str("elasticID", elasticID).Msg("Failed to parse timestamp")
							}
							queryAlert.Timestamp = t
							_, err = s.mongodb.Collection(alertCol).InsertOne(ctx, queryAlert)
							if err != nil {
								logging.GetLogger().Error().Err(err).Str("elasticID", elasticID).Msg("Failed to insert alert from elastic to mongo")
							}
						}
					}
				} else {
					logging.GetLogger().Error().Err(err).Str("elasticID", elasticID).Msg("Failed to check if alert is already recognized by the system")
				}
			} else {
				logging.GetLogger().Error().Err(err).Msg("Polled alert that is already recognized by the platform")
			}
			results = append(results, queryAlert)
		}
	}
	fmt.Printf("Upserting %+v to mongo\n", results)
	s.lastPollTimestamp = lastPollTimestampTo
	return nil
}

func (s *AlertService) AcknowledgeAlert(ctx context.Context, alertObjectID primitive.ObjectID) (*alert.Alert, error) {
	var queryAlert alert.Alert
	filter := bson.M{"_id": alertObjectID}

	queryResult := s.mongodb.Collection(alertCol).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err := queryResult.Decode(&queryAlert)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	if queryAlert.Acknowledged {
		return nil, NewAlertAlreadyAcknowledgedError(http.StatusBadRequest, fmt.Errorf("Alert already acknowledged"))
	}

	queryAlert.Acknowledged = true
	queryAlert.ID = alertObjectID
	update := bson.M{"$set": queryAlert}

	_, err = s.mongodb.Collection(alertCol).UpdateOne(ctx, filter, update)

	queryResult = s.mongodb.Collection(alertCol).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err = queryResult.Decode(&queryAlert)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}

	return &queryAlert, nil
}

func (s *AlertService) ListAlerts(ctx context.Context, offset int64, limit int64, onlyNotAcknowledged bool) ([]alert.Alert, int64, error) {
	filter := bson.M{}
	if onlyNotAcknowledged {
		filter = bson.M{"acknowledged": false}
	}

	var alerts []alert.Alert
	opts := options.Find()
	opts.SetSkip(offset)
	opts.SetLimit(limit)
	opts.SetSort(bson.D{{"cvss3Score", -1}, {"timestamp", -1}})
	coll := s.mongodb.Collection(alertCol)

	cur, err := coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cur.Close(ctx)

	for cur.Next(ctx) {
		//Create a value into which the single document can be decoded
		var elem alert.Alert
		err := cur.Decode(&elem)
		if err != nil {
			return nil, 0, err
		}
		alerts = append(alerts, elem)
	}

	docNum, err := coll.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	return alerts, docNum, err
}

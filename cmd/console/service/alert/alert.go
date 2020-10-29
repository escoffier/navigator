package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/alert"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	alertCol = "alert"
)

type AlertService struct {
	elasticIndex  string
	elasticClient *elastic.Client
	mongodb       *mongo.Database
}

func NewAlertService(es *elastic.Client, elasticIndex string, mongodb *mongo.Database) *AlertService {
	return &AlertService{
		elasticIndex:  elasticIndex,
		elasticClient: es,
		mongodb:       mongodb,
	}
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

func (s *AlertService) ListAlerts(ctx context.Context, offset int64, limit int64) ([]alert.Alert, int64, error) {
	var buf bytes.Buffer

	query := fmt.Sprintf(`{"query": {"match_all" : {}},"size": %d}`, limit)

	var b strings.Builder
	b.WriteString(query)
	read := strings.NewReader(b.String())

	if err := json.NewEncoder(&buf).Encode(read); err != nil {
		return []alert.Alert{}, 0, NewElasticError(http.StatusInternalServerError, fmt.Errorf("Couldn't prepare query: %w", err))
	}

	searchResult, err := s.elasticClient.Search().
		Index(s.elasticIndex).
		Source(query).
		Pretty(true).
		Do(ctx)
	if err != nil {
		return []alert.Alert{}, 0, NewElasticError(http.StatusInternalServerError, fmt.Errorf("Couldn't search for document: %w", err))
	}

	results := make([]alert.Alert, 0)
	if searchResult.Hits.TotalHits.Value > 0 {
		for _, hit := range searchResult.Hits.Hits {
			var queryAlert alert.Alert
			var elasticAlert alert.ElasticAlertDocSource
			err := json.Unmarshal(hit.Source, &elasticAlert)
			if err != nil {
				return []alert.Alert{}, 0, NewElasticError(http.StatusInternalServerError, fmt.Errorf("Couldn't unmarshal document: %w", err))
			}
			filter := bson.M{"elasticId": elasticAlert.Matched.ID}
			queryResult := s.mongodb.Collection(alertCol).FindOne(ctx, filter)
			if queryResult.Err() != nil {
				if queryResult.Err() == mongo.ErrNoDocuments {
					queryAlert.ID = primitive.NewObjectIDFromTimestamp(time.Now())
					queryAlert.Acknowledged = false
					queryAlert.ContainerID = elasticAlert.Matched.ContainerID
					queryAlert.ElasticID = elasticAlert.Matched.ID
					queryAlert.PodName = elasticAlert.Matched.PodName
					queryAlert.PodUID = elasticAlert.Matched.PodUID
					queryAlert.RuleName = elasticAlert.RuleName
					queryAlert.Timestamp = elasticAlert.Timestamp
					insertResult, err := s.mongodb.Collection(alertCol).InsertOne(ctx, queryAlert)
					if err != nil {
						return []alert.Alert{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document with elasticID %s: %w", queryAlert.ElasticID, err))
					}
					id, ok := insertResult.InsertedID.(primitive.ObjectID)
					if !ok {
						return []alert.Alert{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document ID: %w", queryResult.Err()))
					}
					queryAlert.ID = id
				} else {
					return []alert.Alert{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
				}
			} else {
				err = queryResult.Decode(&queryAlert)
				if err != nil {
					return []alert.Alert{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
				}
			}
			results = append(results, queryAlert)
		}
	}

	return results, int64(len(results)), nil
}

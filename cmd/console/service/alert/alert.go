package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/alert"
)

type AlertService struct {
	ElasticIndex  string
	ElasticClient *elasticsearch.Client
}

func NewAlertService(es *elasticsearch.Client, elasticIndex string) *AlertService {
	return &AlertService{
		ElasticIndex:  elasticIndex,
		ElasticClient: es,
	}
}

func (s *AlertService) ListAlerts(ctx context.Context, offset int64, limit int64) ([]alert.Alert, int64, error) {
	var mapResp map[string]interface{}
	var buf bytes.Buffer

	query := fmt.Sprintf(`{"query": {"match_all" : {}},"size": %d}`, limit)

	var b strings.Builder
	b.WriteString(query)
	read := strings.NewReader(b.String())

	if err := json.NewEncoder(&buf).Encode(read); err != nil {
		return []alert.Alert{}, 0, err
	}

	res, err := s.ElasticClient.Search(
		s.ElasticClient.Search.WithContext(ctx),
		s.ElasticClient.Search.WithIndex(s.ElasticIndex),
		s.ElasticClient.Search.WithBody(read),
		s.ElasticClient.Search.WithTrackTotalHits(true),
		s.ElasticClient.Search.WithPretty(),
	)
	if err != nil {
		return []alert.Alert{}, 0, err
	}
	defer res.Body.Close()

	if err := json.NewDecoder(res.Body).Decode(&mapResp); err != nil {
		return []alert.Alert{}, 0, err
	}

	for _, hit := range mapResp["hits"].(map[string]interface{})["hits"].([]interface{}) {
		doc := hit.(map[string]interface{})
		source := doc["_source"]
		fmt.Println("_source:", source)
	}

	return []alert.Alert{}, 0, nil
}

package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/alert"

	"github.com/elastic/go-elasticsearch/v8"
)

type AlertService struct {
	ElasticHost  string
	ElasticPort  string
	ElasticIndex string
}

func NewAlertService(elasticHost string, elasticPort string, elasticIndex string) *AlertService {
	return &AlertService{
		ElasticHost:  elasticHost,
		ElasticPort:  elasticPort,
		ElasticIndex: elasticIndex,
	}
}

func (s *AlertService) ListAlerts(ctx context.Context, offset int64, limit int64) ([]alert.Alert, int64, error) {
	cfg := elasticsearch.Config{
		Addresses: []string{
			fmt.Sprintf("http://%s:%s", s.ElasticHost, s.ElasticPort),
		},
	}
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return []alert.Alert{}, 0, err
	}

	var mapResp map[string]interface{}
	var buf bytes.Buffer

	query := fmt.Sprintf(`{"query": {"match_all" : {}},"size": %d}`, limit)

	var b strings.Builder
	b.WriteString(query)
	read := strings.NewReader(b.String())

	if err := json.NewEncoder(&buf).Encode(read); err != nil {
		return []alert.Alert{}, 0, err
	}

	res, err := es.Search(
		es.Search.WithContext(ctx),
		es.Search.WithIndex(s.ElasticIndex),
		es.Search.WithBody(read),
		es.Search.WithTrackTotalHits(true),
		es.Search.WithPretty(),
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

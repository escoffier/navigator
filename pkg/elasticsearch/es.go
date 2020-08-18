package elasticsearch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/elastic/go-elasticsearch/v7/esapi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	esIndex  = "logstash*"
	msCutoff = 1000000000000
)

// HandleESResponse handles the response from ES
func HandleESResponse(res *esapi.Response, err error) (map[string]interface{}, error) {
	if err != nil {
		logging.GetLogger().Error().
			Err(err).
			Msg("Error getting response")
		return nil, err
	}
	// Check response status
	if res.IsError() {
		logging.GetLogger().Error().
			Err(errors.New(res.String())).
			Msg("Error in response")
		return nil, err
	}
	// Deserialize the response into a map.
	var r map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		logging.GetLogger().Error().
			Err(err).
			Msg("Error parsing the response body")
		return nil, err
	}
	return r, nil
}

// GetQueryFromRequest returns an ES query from http request
func GetQueryFromRequest(r *http.Request) (string, bytes.Buffer, error) {
	var buf bytes.Buffer

	offset, err := param.QueryUint(r, "offset")
	if err != nil {
		offset = 0
	}

	limit, err := param.QueryUint(r, "limit")
	if err != nil {
		limit = 500
	}

	message, err := param.QueryString(r, "message")
	if err != nil {
		message = "*"
	} else {
		message = fmt.Sprintf("*%s*", message)
	}

	var fromStr string
	from, err := param.QueryUint(r, "from")
	if err != nil {
		fromStr = time.Now().Add(-15 * time.Minute).Format("2006-01-02T15:04:05.000Z")
	} else {
		if from < msCutoff {
			fromStr = time.Unix(int64(from), 0).Format("2006-01-02T15:04:05.000Z")
		} else {
			fromStr = time.Unix(0, int64(from)*int64(time.Millisecond)).
				Format("2006-01-02T15:04:05.000Z")
		}
	}

	var toStr string
	to, err := param.QueryUint(r, "to")
	if err != nil {
		toStr = time.Now().Format("2006-01-02T15:04:05.000Z")
	} else {
		if to < msCutoff {
			toStr = time.Unix(int64(to), 0).Format("2006-01-02T15:04:05.000Z")
		} else {
			toStr = time.Unix(0, int64(to)*int64(time.Millisecond)).
				Format("2006-01-02T15:04:05.000Z")
		}
	}

	query := map[string]interface{}{
		"from": offset,
		"size": limit,
		"sort": []map[string]interface{}{
			{
				"@timestamp": map[string]interface{}{
					"order":         "desc",
					"unmapped_type": "boolean",
				},
			},
		},
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"query_string": map[string]interface{}{
							"query":            fmt.Sprintf("message: %s", message),
							"analyze_wildcard": true,
						},
					},
					{
						"range": map[string]interface{}{
							"@timestamp": map[string]interface{}{
								"format": "strict_date_optional_time",
								"gte":    fromStr,
								"lte":    toStr,
							},
						},
					},
				},
			},
		},
	}

	err = json.NewEncoder(&buf).Encode(query)
	return esIndex, buf, err
}

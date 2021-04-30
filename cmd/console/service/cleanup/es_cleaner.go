package cleanup

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"io/ioutil"
	"net/http"
)

type ESCleaner struct {
	elasticOpts *flag.ElasticOpts
}

func NewESCleaner(elasticOpts *flag.ElasticOpts) *ESCleaner {
	return &ESCleaner{elasticOpts: elasticOpts}
}

const (
	esRequestsPerSecond = 500
)

func (c *ESCleaner) Clean(ctx context.Context, daysOffset int) error {
	logging.GetLogger().Info().Msgf("es cleaner start, daysOffset:%d", daysOffset)
	url := fmt.Sprintf("http://%s:%s/*-*/_delete_by_query?pretty&requests_per_second=%d",
		c.elasticOpts.Host, c.elasticOpts.Port, esRequestsPerSecond)

	query := fmt.Sprintf(`{
    "query": {
        "range": {
            "@timestamp": {
                "lt": "now-%dd",
                "format": "epoch_millis"
            }
        }
	}
}`, daysOffset)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(query)))
	if err != nil {
		return fmt.Errorf("new http request fail: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(c.elasticOpts.Username, c.elasticOpts.Password)

	httpClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	cleanFunc := func() error {
		var innerErr error
		rsp, innerErr := httpClient.Do(req.WithContext(ctx))
		if innerErr != nil {
			return fmt.Errorf("failed to send request to elastic: %w", innerErr)
		}

		// avoid memory leak
		defer rsp.Body.Close()
		body, innerErr := ioutil.ReadAll(rsp.Body)
		if err != nil {
			return fmt.Errorf("read http response body fail:%w", innerErr)
		}

		if rsp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected http status code:%d, response body:%s", rsp.StatusCode, body)
		}

		logging.GetLogger().Info().Msgf("es cleaner finished successfully, response body:%s", body)
		return nil
	}

	return util.WithRetry(cleanFunc, util.DefaultRetryConf)
}

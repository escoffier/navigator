package outputter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	consoleUrlPath = "/internal/scap/scanCallback"
)

type tensorCluster struct {
	Status     int32  `json:"status"`
	ConsoleUrl string `json:"console_url"`
}

func getConsoleUrl(url string) (string, error) {
	if url == "" {
		return "", errors.Errorf("cluster url is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := map[string]string{
		"Cache-Control": "no-cache",
		"Content-Type":  "application/json",
	}
	statusCode, body, err := utils.HTTPRequest(ctx, http.MethodGet, url, headers, nil)
	if err != nil {
		return "", errors.Errorf("Error reading response, %v", err)
	}
	if statusCode != http.StatusOK {
		return "", errors.Errorf("GET method's response code error, code = %d", statusCode)
	}

	clusterInfo := tensorCluster{}
	err = json.Unmarshal(body, &clusterInfo)
	if err != nil {
		return "", errors.Errorf("json unmarshal failed, %v", err)
	}
	if clusterInfo.Status != 0 {
		return "", errors.Errorf("get cluster failed, status : %d", clusterInfo.Status)
	}

	return clusterInfo.ConsoleUrl, nil
}

type callback struct {
	clusterAddr string
	console     bool
}

func NewCallback(clusterAddr string, console bool) Outputter {
	return &callback{
		clusterAddr: clusterAddr,
		console:     console,
	}
}

func (cb *callback) Output(format Formater, data interface{}) error {
	clusterManager := fmt.Sprintf("%s/internal/cluster", cb.clusterAddr)
	consoleUrl, err := getConsoleUrl(clusterManager)
	if err != nil || consoleUrl == "" {
		return err
	}

	logging.GetLogger().Info().Msgf("console url: %s", consoleUrl)

	body, err := format.Serialize(data)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("callback output raw, %v", data)
		return err
	}

	if cb.console {
		logging.GetLogger().Info().Msgf("callback output raw, %s", string(body))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	headers := map[string]string{"Content-Type": "application/json"}

	apiURL := fmt.Sprintf("%s%s", consoleUrl, consoleUrlPath)
	statusCode, _, err := utils.HTTPRequest(ctx, http.MethodPost, apiURL, headers, bytes.NewBuffer(body))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("callback output raw, %s", string(body))
		return err
	}

	if statusCode != http.StatusOK {
		logging.GetLogger().Info().Msgf("callback output raw, %d:%s", statusCode, string(body))
		return err
	}

	return nil
}

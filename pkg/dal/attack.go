package dal

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/httputil"
)

const (
	tokenHeader               = "X-Tensorsec-cicd-key"
	token                     = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
	queryKeyCurDataVersion    = "curDataVersion"
	queyrKeyCurSettingVersion = "curSettingVersion"
)

func LoadAttackRules(ctx context.Context, consoleAddr string, curDataVersion, curSettingVersion int64) (*model.LatestATTCKRuleInfo, error) {
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/api/openapi/ATTCK/latestData", consoleAddr)
	firstQuery := true
	if curDataVersion > 0 {
		connector := "&"
		if firstQuery {
			connector = "?"
		}
		url = fmt.Sprintf("%s%s%s=%d", url, connector, queryKeyCurDataVersion, curDataVersion)
		firstQuery = false
	}
	if curSettingVersion > 0 {
		connector := "&"
		if firstQuery {
			connector = "?"
		}
		url = fmt.Sprintf("%s%s%s=%d", url, connector, queyrKeyCurSettingVersion, curSettingVersion)
		firstQuery = false
	}

	req, err := http.NewRequestWithContext(tctx, http.MethodGet, url, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Create request error. url: %s", url)
		return nil, err
	}

	req.Header.Set(tokenHeader, token)
	resp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("request error. url: %s", url)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logging.GetLogger().Error().Msgf("Status code is %d. url: %s.", resp.StatusCode, url)
		return nil, fmt.Errorf("status code is: %d", resp.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logging.GetLogger().Err(err).Msg("read all error.")
		return nil, err
	}

	var respData attackResp
	err = json.Unmarshal(bodyBytes, &respData)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("json decode error. data: %s", string(bodyBytes))
		return nil, err
	}
	data := respData.Data.Item

	return data, nil
}

type attackResp struct {
	Data struct {
		Item *model.LatestATTCKRuleInfo `json:"item"`
	} `json:"data"`
}

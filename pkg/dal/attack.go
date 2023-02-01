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

var (
	attackClient *http.Client
)

func init() {
	attackClient = httputil.NewClientWithDefault()
	attackClient.Timeout = 10 * time.Second
}

func LoadAttackRules(ctx context.Context, addr string, curVersion, curDataVersion, curSettingVersion int64) (*model.LatestATTCKRuleInfo, error) {
	url := fmt.Sprintf("%s/api/openapi/ATTCK/latestData?curVersion=%d", addr, curVersion)

	if curDataVersion > 0 {
		url = fmt.Sprintf("%s&%s=%d", url, queryKeyCurDataVersion, curDataVersion)
	}
	if curSettingVersion > 0 {
		url = fmt.Sprintf("%s&%s=%d", url, queyrKeyCurSettingVersion, curSettingVersion)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Create request error. url: %s", url)
		return nil, err
	}

	req.Header.Set(tokenHeader, token)
	resp, err := attackClient.Do(req)
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

package dal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gopkg.in/yaml.v2"
)

const (
	tokenHeader               = "X-Tensorsec-cicd-key"
	token                     = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
	queryKeyCurDataVersion    = "curDataVersion"
	queyrKeyCurSettingVersion = "curSettingVersion"
)

func LoadAttackRules(ctx context.Context, consoleAddr string, curDataVersion, curSettingVersion uint64) (*model.LatestATTCKRuleInfo, error) {
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s/api/openapi/ATTCK/latestData", consoleAddr)
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("request error. url: %s", url)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logging.GetLogger().Error().Msgf("Status code is %d. url: %s.", resp.StatusCode, url)
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logging.GetLogger().Error().Msg("read all error.")
		return nil, err
	}

	var respData attackResp
	err = json.Unmarshal(bodyBytes, &respData)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("json decode error. data: %s", string(bodyBytes))
		return nil, err
	}
	data := respData.Data.Item

	if !data.DataChanged {
		return data, nil
	}

	encRuleBytes, err := base64.StdEncoding.DecodeString(data.Data)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("base64 decode error. data: %s", data.Data)
		return nil, err
	}
	_, rulesBytes, _, err := cryption.ReadRulesData(encRuleBytes)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("decrypt error. data: %s", encRuleBytes)
		return nil, err
	}
	var rules []*model.RuleFromYaml
	err = yaml.Unmarshal(rulesBytes, &rules)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("decrypt error. data: %s", encRuleBytes)
		return nil, err
	}
	data.AttackRules = rules

	return data, nil
}

type attackResp struct {
	Data struct {
		Item *model.LatestATTCKRuleInfo `json:"item"`
	} `json:"data"`
}

package echelper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/pb"
)

func (c *SherlockClient) getURL(path string, a ...interface{}) string {
	switch path {
	case "ResetCategoryRules":
		return c.SherlockHost + "/api/v1/palace/internal/rules/reset"
	case "AddDetectionRule":
		return c.SherlockHost + "/api/v1/palace/internal/rules"
	case "RiskStats":
		return fmt.Sprintf(c.SherlockHost+"/api/v1/palace/internal/risk/stats?clusterKey=%s&createdAt=%d", a...)
	}

	return c.SherlockHost
}

type SherlockClient struct {
	SherlockHost string
}

func NewSherlockClient(host string) *SherlockClient {
	return &SherlockClient{
		SherlockHost: host,
	}
}

func (c *SherlockClient) AddDetectionRule(ctx context.Context, rule *pb.DetectionRule) error {
	logging.GetLogger().Debug().Msgf("AddDetectionRule start, url:%s, rule:%v", c.getURL("AddDetectionRule"), rule)

	type Request struct {
		Rule *pb.DetectionRule `json:"Rule"`
	}

	jsonBytes, err := json.Marshal(Request{
		Rule: rule,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.getURL("AddDetectionRule"), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(rsp.Body)
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	logging.GetLogger().Debug().Msgf("AddDetectionRule end, url:%s, req:%s, rsp:%s", c.getURL("AddDetectionRule"), string(jsonBytes), string(body))

	return nil
}

func (c *SherlockClient) ResetCategoryRules(ctx context.Context, category string, rules []*pb.DetectionRule) error {

	logging.GetLogger().Debug().Msgf("ResetCategoryRules start, url:%s, category:%s, rules:%v", c.getURL("ResetCategoryRules"), category, rules)

	type Request struct {
		Category string              `json:"Category"`
		Rules    []*pb.DetectionRule `json:"Rules"`
	}

	jsonBytes, err := json.Marshal(Request{
		Category: category,
		Rules:    rules,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.getURL("ResetCategoryRules"), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(rsp.Body)
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	logging.GetLogger().Debug().Msgf("ResetCategoryRules end, url:%s, req:%s, rsp:%s", c.getURL("ResetCategoryRules"), string(jsonBytes), string(body))

	return nil
}

type RiskStatsItem struct {
	EnKey    string `json:"enKey"`
	ZhKey    string `json:"zhKey"`
	Count    int    `json:"count"`
	Severity int    `json:"severity"`
}

func (c *SherlockClient) RiskStats(ctx context.Context, clusterKey string) (map[string][]RiskStatsItem, error) {
	url := c.getURL("RiskStats", clusterKey, time.Now().Add(-time.Hour*24*7).UnixMilli())

	logging.GetLogger().Debug().Str("url", url).Str("clusterKey", clusterKey).Msg("RiskStats start")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	logging.GetLogger().Debug().Str("url", url).Str("resp", string(body)).Msg("RiskStats end")

	result := struct {
		Code    int                        `json:"code"`
		Message string                     `json:"message"`
		Data    map[string][]RiskStatsItem `json:"data"`
	}{}
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Data, nil
}

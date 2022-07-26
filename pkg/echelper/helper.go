package echelper

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/pb"
)

func (c *SherlockClient) getURL(path string) string {
	base := os.Getenv("SHERLOCK_URL")
	switch path {
	case "ResetCategoryRules":
		return base + "/api/v1/palace/internal/rules/reset"
	case "AddDetectionRule":
		return base + "/api/v1/palace/internal/rules"
	}
	return base
}

type SherlockClient struct{}

func NewSherlockClient() SherlockClient {
	return SherlockClient{}
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

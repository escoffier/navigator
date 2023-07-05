package echelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	netURl "net/url"
	"strings"
	"time"

	json "github.com/json-iterator/go"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/httputil"
	"gitlab.com/security-rd/go-pkg/pb"
)

func (c *SherlockClient) getURL(path string, a ...interface{}) string {
	switch path {
	case "ResetCategoryRules":
		return c.SherlockHost + "/api/v1/palace/internal/rules/reset"
	case "AddDetectionRule":
		return c.SherlockHost + "/api/v1/palace/internal/rules"
	case "RiskStats":
		return fmt.Sprintf(c.SherlockHost+"/api/v1/palace/internal/risk/stats?clusterKey=%s&startAt=%d", a...)
	case "GetRuleTemplates":
		return fmt.Sprintf(c.SherlockHost+"/api/v1/palace/rules/templates?version1=%d", a...)
	case "CreateRuleTemplates":
		return c.SherlockHost + "/api/v1/palace/rules/templates/create"
	case "DeleteRuleTemplates":
		return c.SherlockHost + "/api/v1/palace/rules/templates/delete"
	case "GetRuleTemplatesRules":
		return c.SherlockHost + "/api/v1/palace/rules/templates/rules"
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

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	return nil
}

type KVH struct {
	KVHash KVHash `json:"KVHash"`
}
type KVHash struct {
	ZH KV `json:"zh"`
	EN KV `json:"en"`
}
type KV struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}
type ValueHash struct {
	ZH string `json:"zh"`
	EN string `json:"en"`
}
type CustomKV []KVH
type MultiLanguage map[string]struct {
	ValueHash ValueHash `json:"ValueHash"`
}
type Tags []string
type PalaceRule struct {
	ID            int32         `gorm:"primary_key" column:"id"`
	Version1      string        `column:"version1" json:"Version1"`
	Name          string        `column:"name" json:"Name,omitempty"`
	Category      string        `column:"category" json:"Category,omitempty"`
	Module        string        `column:"module" json:"Module,omitempty"`
	Description   string        `column:"description" json:"Description,omitempty"`
	Severity      int           `column:"severity" json:"Severity,omitempty"`
	CustomKV      CustomKV      `column:"custom_kv" json:"CustomKV,omitempty"`
	MultiLanguage MultiLanguage `column:"multi_language" json:"MultiLanguage,omitempty"`
	Status        int           `column:"status" json:"Status"`
	Tags          Tags          `column:"tags" json:"Tags"`
}

func (c *SherlockClient) ResetCategoryRules(ctx context.Context, category string, rules []*PalaceRule, version string) error {

	type Request struct {
		Version  string        `json:"Version"`
		Category string        `json:"Category"`
		Rules    []*PalaceRule `json:"Rules"`
	}

	jsonBytes, err := json.Marshal(Request{
		Version:  version,
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

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(rsp.Body)

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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	result := struct {
		Data struct {
			Item map[string][]RiskStatsItem `json:"item"`
		} `json:"data"`
	}{}
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Data.Item, nil
}

type SherlockResponse struct {
	Data struct {
		Status int `json:"status"`
	}
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	}
}

func (c *SherlockClient) GetRuleTemplates(ctx context.Context, version1 int, id *int, keyword *string, lang lang.LanguageType) ([]*model.RuleTemplate, error) {

	url := c.getURL("GetRuleTemplates", version1)
	if id != nil {
		url += fmt.Sprintf("&id=%d", *id)
	}
	if keyword != nil {
		url += fmt.Sprintf("&keyword=%s", netURl.QueryEscape(strings.TrimSpace(*keyword)))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Language", string(lang))

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	type Response struct {
		Data struct {
			Status     int                   `json:"status"`
			TotalItems int                   `json:"totalItems"`
			Items      []*model.RuleTemplate `json:"items"`
		}
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    string `json:"data"`
		}
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Data.Status != 0 || result.Error.Message != "" {
		err := errors.New("request sherlock GetRuleTemplates fails")
		if result.Error.Message != "" {
			err = errors.New(result.Error.Message)
		}
		return nil, err
	}

	return result.Data.Items, nil
}

func (c *SherlockClient) CreateRuleTemplates(ctx context.Context, version1 int, name, description, creator string, openedRules []string, lang lang.LanguageType) error {

	url := c.getURL("CreateRuleTemplates")

	type Request struct {
		Version1    int      `json:"version1"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		OpenedRules []string `json:"openedRules"`
		Creator     string   `json:"creator"`
	}

	jsonBytes, err := json.Marshal(Request{
		Version1:    version1,
		Name:        name,
		Description: description,
		OpenedRules: openedRules,
		Creator:     creator,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Language", string(lang))

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return err
	}

	result := SherlockResponse{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if result.Data.Status != 0 || result.Error.Message != "" {
		err := errors.New("request sherlock CreateRuleTemplates fails")
		if result.Error.Message != "" {
			err = errors.New(result.Error.Message)
		}
		return err
	}

	return nil
}

func (c *SherlockClient) DeleteRuleTemplates(ctx context.Context, version1, id int, lang lang.LanguageType) error {

	url := c.getURL("DeleteRuleTemplates")

	type Request struct {
		Version1 int `json:"version1"`
		ID       int `json:"id"`
	}

	jsonBytes, err := json.Marshal(Request{
		Version1: version1,
		ID:       id,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Language", string(lang))

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return err
	}

	result := SherlockResponse{}
	if err = json.Unmarshal(body, &result); err != nil {
		return err
	}

	if result.Data.Status != 0 || result.Error.Message != "" {
		err := errors.New("request sherlock DeleteRuleTemplates fails")
		if result.Error.Message != "" {
			err = errors.New(result.Error.Message)
		}
		return err
	}

	return nil
}

func (c *SherlockClient) GetRuleTemplatesRules(ctx context.Context, version1, id int, keyword *string, ruleType *[]string, urgency *[]bool, severity *[]int, _switch *[]bool, lang lang.LanguageType) ([]*model.RuleTemplateRule, error) {

	url := c.getURL("GetRuleTemplatesRules")

	type Request struct {
		Version1 int       `json:"version1"`
		ID       int       `json:"id"`
		Keyword  *string   `json:"keyword,omitempty"`
		RuleType *[]string `json:"rule_type,omitempty"`
		Urgency  *[]bool   `json:"urgency,omitempty"`
		Severity *[]int    `json:"severity,omitempty"`
		Switch   *[]bool   `json:"switch,omitempty"`
	}

	jsonBytes, err := json.Marshal(Request{
		Version1: version1,
		ID:       id,
		Keyword:  keyword,
		RuleType: ruleType,
		Urgency:  urgency,
		Severity: severity,
		Switch:   _switch,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Language", string(lang))

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	type Response struct {
		Data struct {
			Status     int                       `json:"status"`
			TotalItems int                       `json:"totalItems"`
			Items      []*model.RuleTemplateRule `json:"items"`
		}
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    string `json:"data"`
		}
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Data.Status != 0 || result.Error.Message != "" {
		err := errors.New("request sherlock GetRuleTemplatesRules fails")
		if result.Error.Message != "" {
			err = errors.New(result.Error.Message)
		}
		return nil, err
	}

	return result.Data.Items, nil
}

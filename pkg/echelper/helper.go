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
	pkgModel "gitlab.com/security-rd/go-pkg/model"
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
	case "FindWafDetections":
		return fmt.Sprintf(c.SherlockHost + "/api/v1/palace/wafDetections")
	case "GetWafDetectionDetail":
		return fmt.Sprintf(c.SherlockHost+"/api/v1/palace/wafDetections/detail?id=%s", a...)
	case "FindMicroSegLogs":
		return fmt.Sprintf(c.SherlockHost + "/api/v1/palace/microSegLogs")
	case "GetMicroSegLogDetail":
		return fmt.Sprintf(c.SherlockHost+"/api/v1/palace/microSegLogs/detail?id=%s", a...)
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

func (c *SherlockClient) FindWafDetections(ctx context.Context, serviceID *int64, clusterKey, attackedURL, attackIP, attackedApp *string, attackTypes, actions *[]string, startTime, endTime *int64, offset, limit int, token string) ([]*pkgModel.WafDetection, string, error) {
	wafDetections := make([]*pkgModel.WafDetection, 0)

	type listPagination struct {
		Token  string `json:"token"`
		Offset int    `json:"offset"`
		Limit  int    `json:"limit"`
	}
	type Request struct {
		ServiceID   *int64         `json:"service_id"`
		ClusterKey  *string        `json:"cluster_key"`
		AttackedURL *string        `json:"attacked_url"`
		AttackIP    *string        `json:"attack_ip"`
		AttackedApp *string        `json:"attacked_app"`
		AttackTypes *[]string      `json:"attack_types"`
		Actions     *[]string      `json:"actions"`
		StartTime   *int64         `json:"start_time"`
		EndTime     *int64         `json:"end_time"`
		Page        listPagination `json:"page"`
	}

	jsonBytes, err := json.Marshal(Request{
		ServiceID:   serviceID,
		ClusterKey:  clusterKey,
		AttackedURL: attackedURL,
		AttackIP:    attackIP,
		AttackedApp: attackedApp,
		AttackTypes: attackTypes,
		Actions:     actions,
		StartTime:   startTime,
		EndTime:     endTime,
		Page: listPagination{
			Offset: offset,
			Limit:  limit,
			Token:  token,
		},
	})
	if err != nil {
		return wafDetections, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.getURL("FindWafDetections"), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return wafDetections, "", err
	}

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, "", err
	}

	type Response struct {
		Data struct {
			Status    int                      `json:"status"`
			Items     []*pkgModel.WafDetection `json:"items"`
			PageToken string                   `json:"pageToken,omitempty"`
		}
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    string `json:"data"`
		}
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, "", err
	}

	if result.Data.Status != 0 || result.Error.Message != "" {
		err := errors.New("request sherlock FindWafDetections fails")
		if result.Error.Message != "" {
			err = errors.New(result.Error.Message)
		}
		return nil, "", err
	}

	return result.Data.Items, result.Data.PageToken, nil
}

func (c *SherlockClient) GetWafDetectionDetail(ctx context.Context, id string) (*pkgModel.WafDetection, error) {

	url := c.getURL("GetWafDetectionDetail", id)
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

	type Response struct {
		Data struct {
			Status int                    `json:"status"`
			Item   *pkgModel.WafDetection `json:"item"`
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
		err := errors.New("request sherlock GetWafDetectionDetail fails")
		if result.Error.Message != "" {
			err = errors.New(result.Error.Message)
		}
		return nil, err
	}

	return result.Data.Item, nil
}

func (c *SherlockClient) FindMicroSegLogs(ctx context.Context, srcIP, dstIP, srcResName, dstResName *string, proto, action *[]int, clusterKey *string, offset, limit int, token string) ([]*pkgModel.TensorMicrosegEvent, string, error) {
	microsegEvents := make([]*pkgModel.TensorMicrosegEvent, 0)

	type listPagination struct {
		Token  string `json:"token"`
		Offset int    `json:"offset"`
		Limit  int    `json:"limit"`
	}
	type Request struct {
		SrcIP      *string        `json:"src_ip"`
		DstIP      *string        `json:"dst_ip"`
		SrcResName *string        `json:"src_res_name"`
		DstResName *string        `json:"dst_res_name"`
		Proto      *[]int         `json:"proto"`
		Action     *[]int         `json:"action"`
		ClusterKey *string        `json:"cluster_key"`
		Page       listPagination `json:"page"`
	}

	jsonBytes, err := json.Marshal(Request{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcResName: srcResName,
		DstResName: dstResName,
		Proto:      proto,
		Action:     action,
		ClusterKey: clusterKey,
		Page: listPagination{
			Offset: offset,
			Limit:  limit,
			Token:  token,
		},
	})
	if err != nil {
		return microsegEvents, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.getURL("FindMicroSegLogs"), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return microsegEvents, "", err
	}

	rsp, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer util.CloseBodyWithLog(rsp.Body)

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, "", err
	}

	type Response struct {
		Data struct {
			Status    int                             `json:"status"`
			Items     []*pkgModel.TensorMicrosegEvent `json:"items"`
			PageToken string                          `json:"pageToken,omitempty"`
		}
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    string `json:"data"`
		}
	}

	result := Response{}
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, "", err
	}

	if result.Data.Status != 0 || result.Error.Message != "" {
		err := errors.New("request sherlock FindMicroSegLogs fails")
		if result.Error.Message != "" {
			err = errors.New(result.Error.Message)
		}
		return nil, "", err
	}

	return result.Data.Items, result.Data.PageToken, nil
}

func (c *SherlockClient) GetMicroSegLogDetail(ctx context.Context, id string) (*pkgModel.TensorMicrosegEvent, error) {

	url := c.getURL("GetMicroSegLogDetail", id)
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

	type Response struct {
		Data struct {
			Status int                           `json:"status"`
			Item   *pkgModel.TensorMicrosegEvent `json:"item"`
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
		err := errors.New("request sherlock GetMicroSegLogDetail fails")
		if result.Error.Message != "" {
			err = errors.New(result.Error.Message)
		}
		return nil, err
	}

	return result.Data.Item, nil
}

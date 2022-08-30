package ci

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
)

func NewWebhookManager(dal store.ScanCiInterface) WebhookManager {
	return WebhookManager{dal: dal}
}

type WebhookManager struct {
	dal store.ScanCiInterface
}
type WebhookReq struct {
	ID      int64  `json:"id"`
	Enable  bool   `json:"enable"`
	URL     string `json:"url"`
	Secret  string `json:"secret"`
	Options string `json:"options"`
}

func (w *WebhookManager) transWebhookReq(web WebhookReq) scanner_ci.Webhook {
	res := scanner_ci.Webhook{URL: web.URL, Secret: web.Secret, ID: web.ID, Enable: web.Enable}
	var flag int64
	if web.Options == "" {
		return res
	}
	for _, v := range strings.Split(web.Options, ",") {
		if vv, ok := scanner_ci.ConstWebhookString[v]; ok {
			flag += int64(vv)
		}
	}
	res.Flag = flag
	return res
}

func (w *WebhookManager) transWebhook(web scanner_ci.Webhook) WebhookReq {
	res := WebhookReq{URL: web.URL, Secret: web.Secret, ID: web.ID, Enable: web.Enable}
	options := []string{}
	for k, v := range scanner_ci.ConstWebhookString {
		if web.Flag&v > 0 {
			options = append(options, k)
		}
	}
	res.Options = strings.Join(options, ",")
	return res
}

func (w *WebhookManager) CreateWebhook(ctx context.Context, web WebhookReq) error {
	wh := w.transWebhookReq(web)
	err := w.dal.CreateWebhook(ctx, wh)
	if err != nil {
		return err
	}
	return nil
}

func (w *WebhookManager) UpdateWebhook(ctx context.Context, web WebhookReq) error {
	wh := w.transWebhookReq(web)
	tmp, err := w.dal.GetWebhook(ctx)
	if err != nil {
		return err
	}
	if tmp.ID != 0 {
		wh.ID = tmp.ID
		err := w.dal.UpdateWebhook(ctx, wh, tmp.ID)
		if err != nil {
			return err
		}
	} else {
		err := w.dal.CreateWebhook(ctx, wh)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *WebhookManager) GetWebhookRecords(ctx context.Context, limit int, offset int) ([]scanner_ci.WebhookRecord, int64, error) {
	return w.dal.GetWebhookRecords(ctx, limit, offset)
}

func (w *WebhookManager) GetWebhook(ctx context.Context) (WebhookReq, error) {
	resWeb, err := w.dal.GetWebhook(ctx)
	res := w.transWebhook(resWeb)
	if err != nil {
		return res, err
	}
	return res, nil
}

func (w *WebhookManager) CreateWebhookRecord(ctx context.Context, record scanner_ci.WebhookRecord) {
	w.dal.CreateWebhookRecord(ctx, record)
}

func (w *WebhookManager) addHistogram(pkg *scanner_ci.PkgList, Severity string) {
	switch Severity {
	case "CRITICAL":
		pkg.Histogram.NumCritical++
	case "HIGH":
		pkg.Histogram.NumHigh++
	case "MEDIUM":
		pkg.Histogram.NumMedium++
	case "LOW":
		pkg.Histogram.NumLow++
	case "UNKNOWN":
		pkg.Histogram.NumUnknown++
	}
}

func (w *WebhookManager) GetPkgList(result scanner_ci.PolicyResult) []scanner_ci.PkgList {
	mp := make(map[string]scanner_ci.PkgList)
	for _, res := range result.Vulnerabilities.Results {
		for _, vv := range res.Vulnerabilities {
			key := fmt.Sprintf("%s:%s", vv.PkgName, vv.InstalledVersion)
			if v, ok := mp[key]; ok {
				w.addHistogram(&v, vv.Severity)
			} else {
				tmp := scanner_ci.PkgList{PkgName: vv.PkgName, PkgVersion: vv.InstalledVersion}
				w.addHistogram(&tmp, vv.Severity)
				mp[key] = tmp
			}
		}
	}

	for _, v := range result.Artifact.Artifact.Packages {
		key := fmt.Sprintf("%s:%s", v.Name, v.Version)
		if _, ok := mp[key]; ok {
			continue
		}
		mp[key] = scanner_ci.PkgList{PkgName: v.Name, PkgVersion: v.Version}
	}

	res := []scanner_ci.PkgList{}
	for k := range mp {
		res = append(res, mp[k])
	}
	return res
}

func (w *WebhookManager) GetVulnList(result scanner_ci.PolicyResult) []scanner_ci.WebhookVulnList {
	mpBlack := make(map[string]struct{})
	for _, v := range result.MatchVulns.BlackListResults {
		mpBlack[v.VulnerabilityID] = struct{}{}
	}
	for _, v := range result.MatchVulns.SeverityResults {
		mpBlack[v.VulnerabilityID] = struct{}{}
	}
	mp := make(map[string]scanner_ci.WebhookVulnList)
	res := []scanner_ci.WebhookVulnList{}
	for _, res := range result.Vulnerabilities.Results {
		for _, vv := range res.Vulnerabilities {
			if _, ok := mp[vv.VulnerabilityID]; !ok {
				tmp := scanner_ci.WebhookVulnList{
					Name:       vv.VulnerabilityID,
					Severity:   vv.Severity,
					PkgName:    vv.PkgName,
					PkgVersion: vv.InstalledVersion,
					FixedBy:    vv.FixedVersion,
				}
				if _, ok := mpBlack[vv.VulnerabilityID]; ok {
					tmp.Match = 1
				}
				mp[vv.VulnerabilityID] = tmp
			}
		}
	}
	for k, _ := range mp {
		res = append(res, mp[k])
	}
	return res
}

func (w *WebhookManager) TriggerWebhook(ctx context.Context, result scanner_ci.PolicyResult) error {
	webhook, err := w.dal.GetWebhook(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("get webhook error")
		return err
	}
	if !webhook.Enable {
		logging.GetLogger().Warn().Msgf("webhook not enable")
		return nil
	}
	resultCode := int64(1 << result.PolicyResultCode)
	if webhook.Flag&resultCode == 0 {
		logging.GetLogger().Warn().Msgf("policy not need webhook")
		return nil
	}
	record := scanner_ci.WebhookRecord{SendTime: time.Now(), RequestID: result.UUID}
	action := ""
	var alertCode int64
	var blockCode int64
	alertCode = (1 << scanner_ci.CiPolicyResultCodeAlert)
	blockCode = (1 << scanner_ci.CiPolicyResultCodeBlock)
	if result.PolicyResultCode == scanner_ci.CiPolicyResultCodeAlert && webhook.Flag&resultCode == alertCode {
		action = scanner_ci.CiActionAlert
	}
	if result.PolicyResultCode == scanner_ci.CiPolicyResultCodeBlock && webhook.Flag&resultCode == blockCode {
		action = scanner_ci.CiActionBlock
	}
	pkgs := w.GetPkgList(result)
	vulns := w.GetVulnList(result)
	whBody := scanner_ci.WebHookBody{Action: action, Image: result.Artifact.ImageName,
		Vuln: vulns, Sensitive: result.MatchSensitiveFiles, Pkg: pkgs}

	resultByte, err := json.Marshal(whBody)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("marshal result error")
		record.Status = 1
		record.ErrMsg = fmt.Sprintf("结果集解析错误")
		w.CreateWebhookRecord(ctx, record)
		return err
	}
	body := bytes.NewReader(resultByte)
	fmt.Println(webhook.URL)
	req, err := http.NewRequest("POST", webhook.URL, body)
	if err != nil {
		record.Status = 1
		record.ErrMsg = fmt.Sprintf("请求生成错误")
		w.CreateWebhookRecord(ctx, record)
		logging.GetLogger().Err(err).Msgf("NewRequest error")
		return err
	}
	if result.PolicyResultCode == scanner_ci.CiPolicyResultCodeAlert && webhook.Flag&resultCode == alertCode {
		req.Header.Set("X-IVAN-EVENT", "ci-alert")
	}
	if result.PolicyResultCode == scanner_ci.CiPolicyResultCodeBlock && webhook.Flag&resultCode == blockCode {
		req.Header.Set("X-IVAN-EVENT", "ci-block")
	}

	if webhook.Secret != "" {
		req.Header.Set("X-IVAN-TOKEN", webhook.Secret)
		req.Header.Set("X-IVAN-Signature-256", w.HMACSHA1(webhook.Secret, resultByte))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IVAN-Hookshot")
	req.Header.Set("X-IVAN-Delivery", result.UUID)
	cli := http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		record.Status = 1
		record.ErrMsg = fmt.Sprintf("请求失败")
		w.CreateWebhookRecord(ctx, record)
		logging.GetLogger().Err(err).Msgf("request error")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 400 {
		record.Status = 1
		record.ErrMsg = fmt.Sprintf("请求返回代码错误 %d", resp.StatusCode)
		w.CreateWebhookRecord(ctx, record)
		logging.GetLogger().Error().Msgf("resp code error code %d", resp.StatusCode)
		return fmt.Errorf(fmt.Sprintf("resp code error code %d", resp.StatusCode))
	}
	w.CreateWebhookRecord(ctx, record)
	return nil
}

func (w *WebhookManager) HMACSHA1(keyStr string, value []byte) string {

	key := []byte(keyStr)
	mac := hmac.New(sha1.New, key)
	mac.Write(value)
	// 进行base64编码
	res := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return res
}

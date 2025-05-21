package codesec

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/utils"
)

type VulStatistic struct {
	VulNum         int64 `json:"vulNum"`
	VulCriticalNum int64 `json:"vulCriticalNum"`
	VulHighNum     int64 `json:"vulHighNum"`
	VulMediumNum   int64 `json:"vulMediumNum"`
	VulLowNum      int64 `json:"vulLowNum"`
	VulNoRisk      int64 `json:"vulNoRisk"`
}

type LanguageTop struct {
	Name   string `json:"name"`
	VulNum int    `json:"vulNum"`
}

type DashboardParam struct {
	AccessSecret string
	AccessKey    string
}

func CountVulStatistics(baseUrl string, param DashboardParam) (*VulStatistic, error) {
	// 首页代码缺陷数据统计
	apiURL := fmt.Sprintf("%s/cs/api/v4/dashboard/countVulStatistics", baseUrl)
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	header := utils.BuildV2Header(nil, param.AccessKey, param.AccessSecret, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {

		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	var result struct {
		Status  bool          `json:"status"`
		Message string        `json:"message"`
		Data    *VulStatistic `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	if !result.Status {
		return nil, fmt.Errorf("CountVulStatisticst failed: %s", result.Message)
	}
	result.Data.VulNoRisk = max(0, result.Data.VulNum-result.Data.VulCriticalNum-result.Data.VulHighNum-result.Data.VulMediumNum-result.Data.VulLowNum)

	return result.Data, nil
}

func LanguageTop5Statistics(baseUrl string, param DashboardParam) ([]LanguageTop, error) {
	// 开发语言缺陷TOP5统计
	apiURL := fmt.Sprintf("%s/cs/api/v4/dashboard/languageTop5Statistics", baseUrl)
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {

		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	header := utils.BuildV2Header(nil, param.AccessKey, param.AccessSecret, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	var result struct {
		Status  bool          `json:"status"`
		Message string        `json:"message"`
		Data    []LanguageTop `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	if !result.Status {
		return nil, fmt.Errorf("LanguageTop5Statisticst failed: %s", result.Message)
	}
	return result.Data, nil
}

func VulTypeTop5Statistics(baseUrl string, param DashboardParam) ([]LanguageTop, error) {
	//  超危、高危代码缺陷TOP5统计
	apiURL := fmt.Sprintf("%s/cs/api/v4/dashboard/vulTypeTop5Statistics", baseUrl)
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	header := utils.BuildV2Header(nil, param.AccessKey, param.AccessSecret, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	var result struct {
		Status  bool          `json:"status"`
		Message string        `json:"message"`
		Data    []LanguageTop `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	if !result.Status {
		return nil, fmt.Errorf("VulTypeTop5Statistics failed: %s", result.Message)
	}
	return result.Data, nil
}

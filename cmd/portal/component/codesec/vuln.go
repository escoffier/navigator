package codesec

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/store"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/utils"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

// ScanAPISer 漏洞服务
type ScanAPISer struct {
	BaseURL      string
	AccessKey    string
	AccessSecret string
	scanDal      store.CodesecScanDal
	projectDal   store.ProjectDal
	HTTPClient   *http.Client
	Log          *scannerUtils.LogEvent
}

// NewScanAPISer 创建漏洞服务实例
func NewScanAPISer(baseUrl string, accessKey, accessSecret string, scanDal store.CodesecScanDal, projectDal store.ProjectDal) *ScanAPISer {
	return &ScanAPISer{
		BaseURL:      baseUrl,
		AccessKey:    accessKey,
		AccessSecret: accessSecret,
		scanDal:      scanDal,
		projectDal:   projectDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule("ScanAPISer"),
			scannerUtils.WithSubModule("codesecScan")),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetScanResult 获取扫描结果
func (s *ScanAPISer) GetScanResult(projectUuid, taskId string) (*ScanResultResponse, error) {
	// 参数验证
	if projectUuid == "" {
		return nil, fmt.Errorf("projectUuid cannot be empty")
	}
	if taskId == "" {
		return nil, fmt.Errorf("taskId cannot be empty")
	}

	s.Log.Info().
		Str("projectUuid", projectUuid).
		Str("taskId", taskId).
		Str("method", "GetScanResult").
		Msg("Starting GetScanResult request")

	// 构建API URL
	apiURL := fmt.Sprintf("%s/cs/api/v4/project/%s/task/%s/getScanResult",
		s.BaseURL, projectUuid, taskId)

	s.Log.Info().
		Str("apiURL", apiURL).
		Str("projectUuid", projectUuid).
		Str("taskId", taskId).
		Str("method", "GetScanResult").
		Msg("Constructed API URL")

	// 创建HTTP请求
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 构建请求头
	header := utils.BuildV2Header(nil, s.AccessKey, s.AccessSecret, []string{projectUuid, taskId})
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	// 解析响应体
	response := &ScanResultResponse{}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	s.Log.Info().
		Str("responseBody", string(all)).
		Str("projectUuid", projectUuid).
		Str("taskId", taskId).
		Str("method", "GetScanResult").
		Msg("Response body received")

	if err := json.Unmarshal(all, response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if !response.Status {
		return nil, fmt.Errorf("API error: %s", response.Message)
	}

	s.Log.Info().
		Str("projectUuid", projectUuid).
		Str("taskId", taskId).
		Str("method", "GetScanResult").
		Int("securityVulNum", response.Data.ScanResult.SecurityVulNum).
		Int("criticalNum", response.Data.ScanResult.CriticalNum).
		Int("highNum", response.Data.ScanResult.HighNum).
		Int("mediumNum", response.Data.ScanResult.MediumNum).
		Int("lowNum", response.Data.ScanResult.LowNum).
		Str("language", response.Data.Language.Name).
		Msg("GetScanResult completed successfully")

	return response, nil
}

// GetAllVuln 分页查询漏洞列表
func (s *ScanAPISer) getVulnList(param VulnerabilityListParam) (*VulnerabilityListResponse, error) {
	// 构建API URL - 根据Java示例，应该使用v2版本的API
	apiURL := fmt.Sprintf("%s/cs/api/v2/project/%s/task/%s/getListDetailByVulDataId",
		s.BaseURL, param.CodesecAppId, param.TaskId)

	// 创建HTTP请求
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 构建查询参数
	params := map[string]interface{}{
		"vulDataId": param.VulDataId,
	}

	// 添加可选参数
	if param.PageCurrent > 0 {
		params["pageCurrent"] = param.PageCurrent
	}
	if param.PageSize > 0 {
		params["pageSize"] = param.PageSize
	}

	// 添加查询参数到URL
	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, fmt.Sprintf("%v", v))
	}
	req.URL.RawQuery = q.Encode()

	// 构建请求头 - 使用 BuildV2Header 方法，将查询参数作为 body 参数传递
	// 根据 Java 示例，查询参数需要包含在签名中
	header := utils.BuildV2Header(params, param.AccessKey, param.AccessSecret, []string{param.CodesecAppId, param.TaskId})
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 发送请求
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	// 解析响应体
	response := &VulnerabilityListResponse{}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if err := json.Unmarshal(all, response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if !response.Status {
		return nil, fmt.Errorf("API error: %s", response.Message)
	}

	return response, nil
}

// GetAllVuln 获取所有漏洞并合并数据
// 注意，当项目在扫描时，接口会报错
func (s *ScanAPISer) GetAllVuln(codesecUuid, taskId string) ([]*model.CodeSecVuln, *model.CodesecSummary, error) {
	// 参数验证
	if codesecUuid == "" {
		return nil, nil, fmt.Errorf("projectUuid cannot be empty")
	}
	if taskId == "" {
		return nil, nil, fmt.Errorf("taskId cannot be empty")
	}

	s.Log.Info().
		Str("codesecUuid", codesecUuid).
		Str("taskId", taskId).
		Str("method", "GetAllVuln").
		Msg("Starting GetAllVuln request")

	// 1. 首先获取扫描结果，获取漏洞分类树
	scanResult, err := s.GetScanResult(codesecUuid, taskId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get scan result: %v", err)
	}
	scr := s.Parse(scanResult, codesecUuid, taskId)

	var all []*model.CodeSecVuln

	// 2. 遍历漏洞分类树，获取所有vulDataId
	vulDataIds := s.ExtractVulDataIds(scanResult.Data.ScanResult.TreeList)
	s.Log.Info().Int("vulDataIds", len(vulDataIds)).Msg("vulDataIds")
	// 3. 对每个vulDataId分页获取漏洞列表
	for _, vulDataId := range vulDataIds {
		vuln, err := s.getAllVulnByVulDataId(codesecUuid, taskId, vulDataId, scanResult.Data.Language)
		if err != nil {
			s.Log.Info().Str("err", err.Error()).Str("projectUuid", codesecUuid).Str("vulDataId", vulDataId).Msg("Failed to get vulnerability list")
			continue
		}
		all = append(all, vuln...)
	}

	s.Log.Info().
		Str("codesecUuid", codesecUuid).
		Str("taskId", taskId).
		Str("method", "GetAllVuln").
		Int("totalVulns", len(all)).
		Int("securityVulNum", scr.SecurityVulNum).
		Int("criticalNum", scr.CriticalNum).
		Int("highNum", scr.HighNum).
		Int("mediumNum", scr.MediumNum).
		Int("lowNum", scr.LowNum).
		Msg("GetAllVuln completed successfully")

	return all, scr, nil
}

// ExtractVulDataIds 从漏洞树中提取所有vulDataId (公有方法用于测试)
func (s *ScanAPISer) ExtractVulDataIds(treeList []TreeListNode) []string {
	var vulDataIds []string

	for _, node := range treeList {
		if node.VulDataId != "" {
			vulDataIds = append(vulDataIds, node.VulDataId)
		}

		// 递归处理子节点
		if len(node.Children) > 0 {
			childIds := s.ExtractVulDataIds(node.Children)
			vulDataIds = append(vulDataIds, childIds...)
		}
	}

	return vulDataIds
}

// getAllVulnByVulDataId 根据vulDataId获取所有漏洞（分页处理）
func (s *ScanAPISer) getAllVulnByVulDataId(codesecUuid, taskId, vulDataId string, language Language) ([]*model.CodeSecVuln, error) {
	all := make([]*model.CodeSecVuln, 0)

	pageSize := 100 // 每页获取100条
	pageCurrent := 1

	for {
		param := VulnerabilityListParam{
			CodesecAppId: codesecUuid,
			TaskId:       taskId,
			VulDataId:    vulDataId,
			AccessSecret: s.AccessSecret,
			AccessKey:    s.AccessKey,
			PageCurrent:  pageCurrent,
			PageSize:     pageSize,
		}

		response, err := s.getVulnList(param)
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability list for vulDataId %s, page %d: %v", vulDataId, pageCurrent, err)
		}

		// 转换为合并的漏洞信息
		for _, vulTrace := range response.Data.VulTraces {
			combined := &model.CodeSecVuln{
				CodesecAppId: codesecUuid,
				TaskId:       taskId,
				VulId:        vulTrace.VulId,
				VulTypeId:    vulTrace.VulTypeId,
				VulTypeName:  vulTrace.Name,
				VulName:      vulTrace.Name,
				Filename:     vulTrace.Filename,
				RowNum:       vulTrace.RowNum,
				VulDataId:    vulTrace.VulDataId,
				VulFlag:      vulTrace.VulFlag,
				TagId:        vulTrace.TagId,
				TagName:      vulTrace.Tag.CnName,
				RiskId:       vulTrace.RiskId,
				RiskName:     vulTrace.Risk.CnName,
				Signer:       vulTrace.Signer,
				LanguageName: language.Name,
				LanguageId:   language.ID,
			}
			all = append(all, combined)
		}

		// 检查是否还有更多页
		if pageCurrent >= response.Data.PageTotal {
			break
		}
		pageCurrent++
	}

	return all, nil
}

// ScanSubProject 发起扫描任务 (4.2.1)
func (s *ScanAPISer) ScanSubProject(projectUuid, appId string) (*ScanSubProjectResponse, error) {
	if projectUuid == "" {
		return nil, fmt.Errorf("projectUuid cannot be empty")
	}
	if appId == "" {
		return nil, fmt.Errorf("appId cannot be empty")
	}

	// 构建API URL
	apiURL := fmt.Sprintf("%s/cs/api/v4/project/%s/task/%s/scanSubProject",
		s.BaseURL, projectUuid, appId)

	// 创建HTTP请求 - POST请求，无请求体
	req, err := http.NewRequest(http.MethodPost, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 构建请求头
	header := utils.BuildV2HeaderWithURL(apiURL, nil, s.AccessKey, s.AccessSecret)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	// 解析响应体
	response := &ScanSubProjectResponse{}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if err := json.Unmarshal(all, response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	s.Log.Info().Str("response", string(all)).Msg("ScanSubProject response")

	if !response.Status {
		return nil, fmt.Errorf("API error: %s", response.Message)
	}

	return response, nil
}

// GetScanProgress 查询扫描进度 (4.2.2)
// 注意：此接口在项目没有扫描任务时会报错
func (s *ScanAPISer) GetScanProgress(projectUuid, appId string) (*model.ScanProgress, error) {
	if projectUuid == "" {
		s.Log.Error().Str("method", "GetScanProgress").Msg("projectUuid cannot be empty")
		return nil, fmt.Errorf("projectUuid cannot be empty")
	}
	if appId == "" {
		s.Log.Error().Str("method", "GetScanProgress").Str("projectUuid", projectUuid).Msg("appId cannot be empty")
		return nil, fmt.Errorf("appId cannot be empty")
	}

	// 构建API URL
	apiURL := fmt.Sprintf("%s/cs/api/v4/project/%s/task/%s/getScanProgess",
		s.BaseURL, projectUuid, appId)

	s.Log.Info().
		Str("method", "GetScanProgress").
		Str("projectUuid", projectUuid).
		Str("appId", appId).
		Str("apiURL", apiURL).
		Msg("Constructed API URL")

	// 创建HTTP请求 - GET请求
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		s.Log.Error().
			Str("method", "GetScanProgress").
			Str("projectUuid", projectUuid).
			Str("appId", appId).
			Str("apiURL", apiURL).
			Err(err).
			Msg("Failed to create HTTP request")
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 构建请求头 - 注意：签名需要在设置查询参数后构建
	// header := utils.BuildV2HeaderWithURL(apiURL, nil, s.AccessKey, s.AccessSecret)
	path := []string{projectUuid, appId}
	header := utils.BuildV2Header(nil, s.AccessKey, s.AccessSecret, path)

	// 设置请求头
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 解析响应体
	response := &GetScanProgressResponse{}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// 记录响应体内容
	s.Log.Info().
		Str("method", "GetScanProgress").
		Str("projectUuid", projectUuid).
		Str("responseBody", string(all)).
		Msg("Response body received")

	if err := json.Unmarshal(all, response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// 检查API响应状态
	if !response.Status {
		return nil, fmt.Errorf("API error: %s", response.Message)
	}

	// 构建返回结果
	res := &model.ScanProgress{
		Msg:        response.Message,
		Progress:   response.Data.Progress,
		CommitId:   response.Data.CommitId,
		ScanTime:   response.Data.ScanTime,
		FinishTime: response.Data.FinishTime,
		SpendTime:  response.Data.SpendTime,
	}

	// 记录成功结果
	s.Log.Info().
		Str("method", "GetScanProgress").
		Str("projectUuid", projectUuid).
		Interface("scanProgress", res).
		Msg("GetScanProgress completed successfully")

	return res, nil
}

// validateAndLogTimestamp 验证并记录时间戳信息
func (s *ScanAPISer) validateAndLogTimestamp(header map[string]string, projectUuid, appId string) {
	timestampStr := header["x-cs-timestamp"]
	if timestampStr == "" {
		s.Log.Error().
			Str("method", "GetScanProgress").
			Str("projectUuid", projectUuid).
			Str("appId", appId).
			Msg("Missing timestamp in header")
		return
	}

	// 解析时间戳
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		s.Log.Error().
			Str("method", "GetScanProgress").
			Str("projectUuid", projectUuid).
			Str("appId", appId).
			Str("timestamp", timestampStr).
			Err(err).
			Msg("Invalid timestamp format")
		return
	}

	// 计算时间差
	now := time.Now().UnixMilli()
	diff := now - timestamp

	s.Log.Info().
		Str("method", "GetScanProgress").
		Str("projectUuid", projectUuid).
		Str("appId", appId).
		Int64("timestamp", timestamp).
		Int64("currentTime", now).
		Int64("timeDiffMs", diff).
		Float64("timeDiffSec", float64(diff)/1000.0).
		Bool("timestampValid", abs(diff) < 300000). // 5分钟内认为有效
		Msg("Timestamp validation")
}

// abs 计算绝对值
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func (s *ScanAPISer) Parse(scanResult *ScanResultResponse, pro, taskID string) *model.CodesecSummary {
	// 2. 转换为数据库存储格式（不包含treeList）
	scanResultRecord := &model.CodesecSummary{
		CodesecUuid:             pro,
		TaskId:                  taskID,
		SecurityVulNum:          scanResult.Data.ScanResult.SecurityVulNum,
		CodeSecurityWeaknessNum: scanResult.Data.ScanResult.CodeSecurityWeaknessNum,
		CriticalNum:             scanResult.Data.ScanResult.CriticalNum,
		HighNum:                 scanResult.Data.ScanResult.HighNum,
		MediumNum:               scanResult.Data.ScanResult.MediumNum,
		LowNum:                  scanResult.Data.ScanResult.LowNum,
		NoteNum:                 scanResult.Data.ScanResult.NoteNum,
		NewDiscoveryNum:         scanResult.Data.ScanResult.NewDiscoveryNum,
		RepeatNum:               scanResult.Data.ScanResult.RepeatNum,
		IsReviseNum:             scanResult.Data.ScanResult.IsReviseNum,
		LibraryNum:              scanResult.Data.ScanResult.LibraryNum,
		CveNum:                  scanResult.Data.ScanResult.CveNum,
		CnnvdNum:                scanResult.Data.ScanResult.CnnvdNum,
		CodeLineNum:             scanResult.Data.ScanResult.CodeLineNum,
		CommentLines:            scanResult.Data.ScanResult.CommentLines,
		BlankLines:              scanResult.Data.ScanResult.BlankLines,
		LanguageId:              scanResult.Data.Language.ID,
		LanguageName:            scanResult.Data.Language.Name,
		CyclomaticComplexityNum: scanResult.Data.CyclomaticComplexityNum,
		RepetitiveLines:         scanResult.Data.RepetitiveLines,
		FileNum:                 scanResult.Data.FileNum,
		FileSize:                scanResult.Data.FileSize,
		GitBranch:               scanResult.GitInfo.Branch,
		GitCommitId:             scanResult.GitInfo.CommitId,
		GitExtraMark:            scanResult.GitInfo.ExtraMark,
		ScanStatus:              consts.ScanStatusSuccess,
	}
	return scanResultRecord
}

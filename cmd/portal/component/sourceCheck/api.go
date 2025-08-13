package sourceCheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

type Api struct {
	DefaultHeader map[string]string
	Authorization string
	BaseURL       string
	Log           *scannerUtils.LogEvent
}

func (s *Api) CreateToken(ctx context.Context, param GetTokenReq) (*GetTokenResp, error) {
	// 定义请求的URL
	url := fmt.Sprintf("%s/%s", s.BaseURL, "sca/v1/tokens")
	bys, err := json.Marshal(param)
	if err != nil {
		return nil, err
	}
	// 创建一个新的请求对象
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bys))
	if err != nil {
		return nil, err
	}
	// 设置自定义请求头
	for k, v := range s.DefaultHeader {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	res := &GetTokenResp{}
	if err := json.Unmarshal(body, res); err != nil {
		return nil, err
	}
	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("create source check token failed: %s", res.Msg)
	}

	return res, nil
}

// GetToken 获取一个 token
func (s *Api) GetToken(ctx context.Context, param GetTokenReq) (*GetTokenResp, error) {
	// 定义请求的URL
	url := fmt.Sprintf("%s/%s", s.BaseURL, "sca/v1/tokens")
	bys, err := json.Marshal(param)
	if err != nil {
		return nil, err
	}
	// 创建一个新的请求对象
	req, err := http.NewRequest(http.MethodGet, url, bytes.NewBuffer(bys))
	if err != nil {
		fmt.Printf("创建请求失败: %v\n", err)
		return nil, err
	}
	// 设置自定义请求头
	for k, v := range s.DefaultHeader {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	res := &GetTokenResp{}
	if err := json.Unmarshal(body, res); err != nil {
		return nil, err
	}
	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("create source check token failed: %s", res.Msg)
	}

	return res, nil
}

// CreateUser 只能是管理员才能创建
func (s *Api) CreateUser(ctx context.Context, use User) error {
	url := fmt.Sprintf("%s/%s", s.BaseURL, "sca/v1/users")
	bys, err := json.Marshal(use)
	if err != nil {
		return err
	}
	// 创建一个新的请求对象
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bys))
	if err != nil {
		fmt.Printf("创建请求失败: %v\n", err)
		return err
	}
	// 设置自定义请求头
	for k, v := range s.DefaultHeader {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// 读取响应体
	res := &CreateUserRes{}
	if err := json.NewDecoder(resp.Body).Decode(res); err != nil {
		return err
	}
	if res.Status != consts.SourceCheckStatusOK {
		return fmt.Errorf("create source check user failed: %s", res.Msg)
	}
	return nil
}

func (s *Api) CreateProject(ctx context.Context, pro *Project) (*CreateProjectResponse, error) {
	url := fmt.Sprintf("%s/%s", s.BaseURL, "sca/v1/applications/repository")
	bys, err := json.Marshal(pro)
	if err != nil {
		return nil, err
	}
	// 创建一个新的请求对象
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bys))
	if err != nil {
		return nil, err
	}
	// 设置自定义请求头
	for k, v := range s.DefaultHeader {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	res := &CreateProjectResponse{}
	if err := json.NewDecoder(resp.Body).Decode(res); err != nil {
		return nil, err
	}
	s.Log.Info().Interface("res", res).Str("url", url).Msg("SourceCheckAPI CreateProject")
	if res.Status != consts.SourceCheckStatusOK {
		return res, fmt.Errorf("create source check project failed: %s", res.Msg)
	}
	return res, nil
}

func (s *Api) UpdateProject(ctx context.Context, uuid string, pro *Project) error {
	pro.AppUuid = uuid
	url := fmt.Sprintf("%s/%s", s.BaseURL, "sca/v1/applications")
	bys, err := json.Marshal(pro)
	if err != nil {
		return err
	}
	// 创建一个新的请求对象
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(bys))
	if err != nil {
		return err
	}
	// 设置自定义请求头
	for k, v := range s.DefaultHeader {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	res := &CreateProjectResponse{}
	if err := json.NewDecoder(resp.Body).Decode(res); err != nil {
		return err
	}
	if s.Log != nil {
		s.Log.Info().Interface("res", res).Str("url", url).Msg("SourceCheckAPI UpdateProject")
	}
	if res.Status != consts.SourceCheckStatusOK {
		return fmt.Errorf("update source check project failed: %s", res.Msg)
	}

	return nil
}

func (s *Api) DeleteProject(ctx context.Context, pro string) error {
	url := fmt.Sprintf("%s/%s/%s", s.BaseURL, "sca/v1/applications", pro)
	// 创建一个新的请求对象
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	// 设置自定义请求头
	for k, v := range s.DefaultHeader {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	res := &CreateUserRes{}
	if err := json.NewDecoder(resp.Body).Decode(res); err != nil {
		return err
	}
	if s.Log != nil {
		s.Log.Info().Interface("res", res).Str("url", url).Str("projectUUID", pro).Msg("SourceCheckAPI DeleteProject")
	}
	if res.Status == consts.SourceCheckStatusOK || strings.Contains(res.Msg, "项目不存在") {
		return nil
	}
	return fmt.Errorf("delete source check project failed: %s", res.Msg)
}

// GetHighRiskComponents 1. 高危组件top10
func (s *Api) GetHighRiskComponents(ctx context.Context, req StatisticsRequest) ([]HighRiskComponent, error) {
	url := fmt.Sprintf("%s/sca/v1/statistics/comp/grade/ten", s.BaseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	for k, v := range s.DefaultHeader {
		httpReq.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var res struct {
		Status int                 `json:"status"`
		Data   []HighRiskComponent `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode response failed: %w", err)
	}
	if s.Log != nil {
		s.Log.Info().Interface("res", res).Str("url", url).Msg("SourceCheckAPI")
	}

	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("API returned error status: %d", res.Status)
	}

	return res.Data, nil
}

// GetMostUsedComponents 2. 被引用最多组件top10
func (s *Api) GetMostUsedComponents(ctx context.Context, req StatisticsRequest) ([]MostUsedComponent, error) {
	url := fmt.Sprintf("%s/sca/v1/statistics/comp/use/ten", s.BaseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	for k, v := range s.DefaultHeader {
		httpReq.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var res struct {
		Status int                 `json:"status"`
		Data   []MostUsedComponent `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode response failed: %w", err)
	}

	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("API returned error status: %d", res.Status)
	}

	for i := range res.Data {
		res.Data[i].Count = convToInt64(res.Data[i].Value)
	}

	return res.Data, nil
}

// GetLicenseStatistics 3. 获取许可统计数据
func (s *Api) GetLicenseStatistics(ctx context.Context, req StatisticsRequest) ([]LicenseStat, error) {
	url := fmt.Sprintf("%s/sca/v1/statistics/license/count", s.BaseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	for k, v := range s.DefaultHeader {
		httpReq.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var res struct {
		Status int           `json:"status"`
		Data   []LicenseStat `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode response failed: %w", err)
	}

	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("API returned error status: %d", res.Status)
	}

	return res.Data, nil
}

// ShareApp 实现应用分享功能,这样首页才能查到全部数据
func (s *Api) ShareApp(ctx context.Context, req ShareAppRequest) error {
	url := fmt.Sprintf("%s/%s", s.BaseURL, "/sca/v1/applications/user")
	bys, err := json.Marshal(req)
	if err != nil {
		return err
	}

	// 创建请求
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bys))
	if err != nil {
		return fmt.Errorf("share app : %v", err)
	}

	// 设置请求头
	for k, v := range s.DefaultHeader {
		httpReq.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	// 解析响应
	res := &BaseResponse{}
	if err := json.NewDecoder(resp.Body).Decode(res); err != nil {
		return err
	}
	if res.Status != consts.SourceCheckStatusOK {
		return fmt.Errorf("API returned error status: %d,%s", res.Status, res.Msg)
	}

	return nil
}

// getVulnerabilityListPage 获取单页漏洞列表
func (s *Api) getVulnerabilityListPage(ctx context.Context, req VulnerabilityListRequest, pageIndex, pageSize int) (*VulnerabilityListResponse, error) {
	// 构建URL和查询参数
	url := fmt.Sprintf("%s/sca/v1/vulnerabilities", s.BaseURL)
	params := fmt.Sprintf("?pageIndex=%d&pageSize=%d", pageIndex, pageSize)

	// 只使用AppUuid参数，因为其他参数已被注释掉
	if req.AppUuid != "" {
		params += fmt.Sprintf("&appUuid=%s", req.AppUuid)
	}

	url += params

	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	// 设置请求头
	for k, v := range s.DefaultHeader {
		httpReq.Header.Set(k, v)
	}

	// 发送请求
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析响应体
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var res VulnerabilityListResponse
	if err := json.Unmarshal(all, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// 记录日志
	if s.Log != nil {
		s.Log.Info().
			Interface("request", map[string]interface{}{
				"pageIndex": pageIndex,
				"pageSize":  pageSize,
				"appUuid":   req.AppUuid,
			}).
			Int("total", res.Data.Total).
			Int("currentPageCount", len(res.Data.DataList)).
			Str("url", url).
			Msg("SourceCheckAPI GetAllVuln")
	}

	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("API returned error status: %d, msg: %s", res.Status, res.Msg)
	}

	return &res, nil
}

// GetAllVuln 获取项目漏洞列表，循环获取所有漏洞
func (s *Api) GetAllVuln(ctx context.Context, req VulnerabilityListRequest) ([]*model.SourceCheckVuln, error) {
	var allVulns []*model.SourceCheckVuln
	pageIndex := 1
	pageSize := 100 // 使用最大页面大小以减少请求次数

	for {
		res, err := s.getVulnerabilityListPage(ctx, req, pageIndex, pageSize)
		if err != nil {
			return nil, err
		}

		// 转换API响应为模型对象
		for _, item := range res.Data.DataList {
			vuln := &model.SourceCheckVuln{
				SourceCheckUuid:      req.AppUuid,
				CustomSzNo:           item.CustomSzNo,
				CustomCveNo:          item.CustomCveNo,
				CustomCnnvdNo:        item.CustomCnnvdNo,
				AffectComponentCount: item.AffectComponentCount,
				CustomCnvdNo:         item.CustomCnvdNo,
				Grade:                item.Grade,
				Cwe:                  item.Cwe,
				VulnerabilityName:    item.VulnerabilityName,
				CweName:              item.CweName,
				Description:          item.Description,
				ReleaseDate:          item.ReleaseDate,
			}
			allVulns = append(allVulns, vuln)
		}

		// 检查是否还有更多数据
		if len(res.Data.DataList) < pageSize || len(allVulns) >= res.Data.Total {
			break
		}

		pageIndex++
	}

	if s.Log != nil {
		s.Log.Info().
			Int("totalVulns", len(allVulns)).
			Str("appUuid", req.AppUuid).
			Msg("SourceCheckAPI GetAllVuln completed")
	}

	return allVulns, nil
}

// getLicenseListPage 获取单页许可列表
func (s *Api) getLicenseListPage(ctx context.Context, req LicenseListRequest, pageIndex, pageSize int) (*LicenseListResponse, error) {
	// 构建URL和查询参数
	url := fmt.Sprintf("%s/sca/v1/licenses", s.BaseURL)
	params := fmt.Sprintf("?pageIndex=%d&pageSize=%d", pageIndex, pageSize)

	// 只使用AppUuid参数，因为其他参数已被注释掉
	if req.AppUuid != "" {
		params += fmt.Sprintf("&appUuid=%s", req.AppUuid)
	}

	url += params

	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	// 设置请求头
	for k, v := range s.DefaultHeader {
		httpReq.Header.Set(k, v)
	}

	// 发送请求
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析响应体
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var res LicenseListResponse
	if err := json.Unmarshal(all, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// 记录日志
	if s.Log != nil {
		s.Log.Info().
			Interface("request", map[string]interface{}{
				"pageIndex": pageIndex,
				"pageSize":  pageSize,
				"appUuid":   req.AppUuid,
			}).
			Int("total", res.Data.Total).
			Int("currentPageCount", len(res.Data.DataList)).
			Str("url", url).
			Msg("SourceCheckAPI GetAllLicense")
	}

	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("API returned error status: %d, msg: %s", res.Status, res.Msg)
	}

	return &res, nil
}

// GetAllLicense 获取许可列表，循环获取所有许可
func (s *Api) GetAllLicense(ctx context.Context, req LicenseListRequest) ([]*model.SourceCheckLicense, error) {
	var allLicenses []*model.SourceCheckLicense
	pageIndex := 1
	pageSize := 500 // 使用最大页面大小以减少请求次数

	for {
		res, err := s.getLicenseListPage(ctx, req, pageIndex, pageSize)
		if err != nil {
			return nil, err
		}

		// 转换API响应为模型对象
		for _, item := range res.Data.DataList {
			license := &model.SourceCheckLicense{
				SourceCheckUuid: req.AppUuid,
				Grade:           item.Grade,
				LicenseId:       item.LicenseId,
				LicenseName:     item.LicenseName,
			}
			allLicenses = append(allLicenses, license)
		}

		// 检查是否还有更多数据
		if len(res.Data.DataList) < pageSize || len(allLicenses) >= res.Data.Total {
			break
		}

		pageIndex++
	}

	if s.Log != nil {
		s.Log.Info().
			Int("totalLicenses", len(allLicenses)).
			Str("appUuid", req.AppUuid).
			Msg("SourceCheckAPI GetAllLicense completed")
	}

	return allLicenses, nil
}

// getComponentListPage 获取单页组件列表
func (s *Api) getComponentListPage(ctx context.Context, req ComponentListRequest, pageIndex, pageSize int) (*ComponentListResponse, error) {
	// 构建URL
	url := fmt.Sprintf("%s/sca/v1/applications/components", s.BaseURL)

	// 构建form-data请求体
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// 添加分页参数
	_ = writer.WriteField("pageIndex", strconv.Itoa(pageIndex))
	_ = writer.WriteField("pageSize", strconv.Itoa(pageSize))

	// 添加必填参数
	if req.AppUuid != "" {
		_ = writer.WriteField("appUuid", req.AppUuid)
	}

	// 由于结构体已简化，不再添加其他可选参数

	// 关闭writer以完成form-data的构建
	err := writer.Close()
	if err != nil {
		return nil, fmt.Errorf("close writer failed: %w", err)
	}

	// 创建请求 - 根据接口文档，应该使用POST方法
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range s.DefaultHeader {
		if k != "Content-Type" { // 避免覆盖form-data的Content-Type
			httpReq.Header.Set(k, v)
		}
	}

	// 发送请求
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析响应体
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var res ComponentListResponse
	if err := json.Unmarshal(all, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// 记录日志
	if s.Log != nil {
		s.Log.Info().
			Interface("request", map[string]interface{}{
				"pageIndex": pageIndex,
				"pageSize":  pageSize,
				"appUuid":   req.AppUuid,
			}).
			Int("total", res.Data.Total).
			Int("currentPageCount", len(res.Data.DataList)).
			Str("url", url).
			Msg("SourceCheckAPI GetAllComponent")
	}

	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("API returned error status: %d, msg: %s", res.Status, res.Msg)
	}

	return &res, nil
}

// GetAllComponent 获取组件列表，循环获取所有组件
func (s *Api) GetAllComponent(ctx context.Context, req ComponentListRequest) ([]*model.SourceCheckComponent, error) {
	var allComponents []*model.SourceCheckComponent
	pageIndex := 1
	pageSize := 500 // 使用最大页面大小以减少请求次数

	for {
		res, err := s.getComponentListPage(ctx, req, pageIndex, pageSize)
		if err != nil {
			return nil, err
		}

		// 转换API响应为模型对象
		for _, item := range res.Data.DataList {
			component := &model.SourceCheckComponent{
				SourceCheckUuid:           req.AppUuid,
				ComponentId:               item.ComponentId,
				GroupId:                   item.GroupId,
				ArtifactId:                item.ArtifactId,
				ComponentUuid:             item.ComponentUuid,
				ControlStatus:             item.ControlStatus,
				ControlStatusName:         item.ControlStatusName,
				DepRank:                   item.DepRank,
				DepScope:                  item.DepScope,
				Reference:                 item.Reference,
				Grade:                     item.Grade,
				JarInfoAddFrom:            item.JarInfoAddFrom,
				Version:                   item.Version,
				RecommendVersion:          item.RecommendVersion,
				AppVersionId:              item.AppVersionId,
				FirstCheckTime:            item.FirstCheckTime,
				LastCheckTime:             item.LastCheckTime,
				Origin:                    item.Origin,
				GradeDesc:                 item.GradeDesc,
				HomePage:                  item.HomePage,
				SourceCode:                item.SourceCode,
				ReleaseTime:               item.ReleaseTime,
				LatestVersion:             item.LatestVersion,
				PrivatePublicStatus:       item.PrivatePublicStatus,
				PrivatePublicStatusName:   item.PrivatePublicStatusName,
				Classifier:                item.Classifier,
				ProjectWhiteControlStatus: item.ProjectWhiteControlStatus,
				Country:                   item.Country,
				CountryChineseName:        item.CountryChineseName,
				VirusFlag:                 item.VirusFlag,
				LicenseIds:                item.LicenseIds,
			}

			// 处理来源信息列表
			if len(item.SourceInfoList) > 0 {
				sourceInfoBytes, _ := json.Marshal(item.SourceInfoList)
				component.SourceInfoList = string(sourceInfoBytes)
			}

			allComponents = append(allComponents, component)
		}

		// 检查是否还有更多数据
		if len(res.Data.DataList) < pageSize || len(allComponents) >= res.Data.Total {
			break
		}

		pageIndex++
	}

	if s.Log != nil {
		s.Log.Info().
			Int("totalComponents", len(allComponents)).
			Str("appUuid", req.AppUuid).
			Msg("SourceCheckAPI GetAllComponent completed")
	}

	return allComponents, nil
}

// StartScan 对应用发起扫描
func (s *Api) StartScan(ctx context.Context, req StartScanRequest) (*StartScanResponse, error) {
	// 参数验证
	if req.AppUuid == "" {
		return nil, fmt.Errorf("appUuid is required")
	}
	if req.CallBackUrl == "" {
		return nil, fmt.Errorf("callBackUrl is required")
	}

	url := fmt.Sprintf("%s/sca/v1/warehouse/applications/detection", s.BaseURL)

	// 使用application/x-www-form-urlencoded格式，根据接口文档3.23.1
	data := fmt.Sprintf("appUuid=%s&callBackUrl=%s", req.AppUuid, req.CallBackUrl)

	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range s.DefaultHeader {
		if k != "Content-Type" { // 避免覆盖form-urlencoded的Content-Type
			httpReq.Header.Set(k, v)
		}
	}

	// 发送请求
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析响应体
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var res StartScanResponse
	if err := json.Unmarshal(all, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// 记录日志
	s.Log.Info().
		Str("appUuid", req.AppUuid).
		Str("callBackUrl", req.CallBackUrl).
		Interface("response", res).
		Str("url", url).
		Msg("SourceCheckAPI StartScan")

	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("API returned error status: %d, msg: %s", res.Status, res.Msg)
	}

	return &res, nil
}

// GetScanProgress 查询扫描状态
// 每个应用只会记录一次checkNo,如果用过期的CheckNo查询会返回错误
func (s *Api) GetScanProgress(ctx context.Context, checkNo string) (*ScanProgressResponse, error) {
	url := fmt.Sprintf("%s/sca/v1/applications/progress/%s", s.BaseURL, checkNo)

	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	// 设置请求头
	for k, v := range s.DefaultHeader {
		httpReq.Header.Set(k, v)
	}

	// 发送请求
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析响应体
	var res GetScanProgressResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode response failed: %w", err)
	}

	// 记录日志
	s.Log.Info().
		Str("checkNo", checkNo).
		Interface("response", res).
		Str("url", url).
		Msg("SourceCheckAPI GetScanProgress")

	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("API returned error status: %d, msg: %s", res.Status, res.Msg)
	}

	return res.Data, nil
}

func NewApi(opts ...Option) *Api {
	s := &Api{
		DefaultHeader: map[string]string{
			"Content-Type": "application/json",
		},
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule("SourceCheck"),
			scannerUtils.WithSubModule("api")),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.Authorization != "" {
		s.DefaultHeader["Authorization"] = fmt.Sprintf("BASIC-API:%s", s.Authorization)
	}

	return s
}

type Option func(a *Api)

func WithAuthorization(au string) Option {
	return func(a *Api) {
		a.Authorization = au
	}
}

func WithBaseURL(url string) Option {
	return func(a *Api) {
		a.BaseURL = url
	}
}

type CreateUserRes struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
}

func convToInt64(a string) int64 {
	str, _ := strconv.ParseInt(a, 10, 64)
	return str
}

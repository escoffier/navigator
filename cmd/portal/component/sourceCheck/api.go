package sourceCheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/consts"
	"gitlab.com/security-rd/go-pkg/logging"
)

type Api struct {
	DefaultHeader map[string]string
	Authorization string
	BaseURL       string
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
	logging.Get().Info().Interface("res", res).Str("url", url).Msg("SourceCheckAPI CreateProject")
	if res.Status != consts.SourceCheckStatusOK {
		return nil, fmt.Errorf("create source check project failed: %s", res.Msg)
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
	logging.Get().Info().Interface("res", res).Str("url", url).Msg("SourceCheckAPI UpdateProject")
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
	logging.Get().Info().Interface("res", res).Str("url", url).Str("projectUUID", pro).Msg("SourceCheckAPI DeleteProject")
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
	logging.Get().Info().Interface("res", res).Str("url", url).Msg("SourceCheckAPI")

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

// ShareApp 实现应用分享功能
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

func NewApi(opts ...Option) *Api {
	s := &Api{
		DefaultHeader: map[string]string{
			"Content-Type": "application/json",
		},
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

package codesec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/utils"
	"gitlab.com/security-rd/go-pkg/logging"
)

type User struct {
	UserName    string `json:"userName,omitempty"`
	UserEmail   string `json:"userEmail"`
	Password    string `json:"password"`
	Phone       string `json:"phone,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	// KeyExpiredDate string `json:"keyExpiredDate,omitempty"`
}

// CreateUserParam 定义创建账号的请求结构体
type CreateUserParam struct {
	User         User
	AccessSecret string
	AccessKey    string
}

// CreateUserResponse 定义创建账号的响应结构体
type CreateUserResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		AccessKey    string `json:"accessKey"`
		AccessSecret string `json:"accessSecret"`
	} `json:"data"`
}

func CreateUser(baseUrl string, request CreateUserParam) (*CreateUserResponse, error) {
	// 将请求结构体转换为JSON
	apiURL := fmt.Sprintf("%s/%s", baseUrl, "cs/api/v4/user/createAccount")
	requestBody, err := json.Marshal(request.User)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}
	data := map[string]interface{}{}
	_ = json.Unmarshal(requestBody, &data)
	header := utils.BuildV2Header(data, request.AccessKey, request.AccessSecret, nil)
	// 创建一个新的请求对象
	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	// 设置自定义请求头
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析响应体
	response := &CreateUserResponse{}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	logging.Get().Info().Str("url", apiURL).Str("res", string(all)).Msg("Codesec resp")
	if err := json.Unmarshal(all, response); err != nil {
		return nil, err
	}
	if !response.Status {
		return nil, fmt.Errorf("create user failed: %s", response.Message)
	}
	return response, nil
}

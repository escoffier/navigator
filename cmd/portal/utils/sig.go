package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BuildV2HeaderWithURL 根据完整URL构建V2请求头
// 根据codesec API文档和Java示例实现签名机制
func BuildV2HeaderWithURL(fullURL string, params map[string]interface{}, accessKey, accusesSecret string) map[string]string {
	headers := map[string]string{
		"accessKey":      accessKey,
		"x-cs-timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10),
		"x-cs-nonce":     uuid.New().String(),
	}

	// 1. 处理请求体参数（Body参数）- 按照Java版本的mergeBody逻辑
	var bodyData string

	// 2. 处理URL路径参数 - 按照Java版本的matchesUrl逻辑
	pathValue := extractURLPath(fullURL)

	// 3. 构建签名数据 - 按照文档规范
	// 签名串拼接顺序：先拼接Body，再拼接PathValue，最后&客户端密钥&时间戳&随机字符
	var signData string
	endPart := "&" + accusesSecret + "&" + headers["x-cs-timestamp"] + "&" + headers["x-cs-nonce"]

	if bodyData == "" {
		// 没有请求体参数
		if pathValue == "" {
			// 既没有请求体参数也没有路径参数
			signData = endPart
		} else {
			// 只有路径参数，去掉开头的&
			signData = pathValue[1:] + endPart
		}
	} else {
		// 有请求体参数
		if pathValue == "" {
			// 只有请求体参数
			signData = bodyData + endPart
		} else {
			// 既有请求体参数也有路径参数
			signData = bodyData + pathValue + endPart
		}
	}

	// 清理开头的&符号（防御性编程）
	if strings.HasPrefix(signData, "&") {
		signData = signData[1:]
	}

	// 4. 计算SHA256签名
	hash := sha256.Sum256([]byte(signData))
	signature := hex.EncodeToString(hash[:])
	headers["x-cs-signature"] = signature

	return headers
}

func extractURLPath(fullURL string) string {
	// 解析URL
	u, err := url.Parse(fullURL)
	if err != nil {
		return ""
	}

	path := u.Path

	// 检查是否包含API路径
	antFilterPaths := []string{"/cs/api/v2", "/cs/api/v3", "/cs/api/v4"}
	var apiPath string
	for _, filterPath := range antFilterPaths {
		if strings.Contains(path, filterPath) {
			apiPath = filterPath
			break
		}
	}

	if apiPath == "" {
		return ""
	}

	// 移除API前缀
	path = strings.Replace(path, apiPath, "", 1)

	// URL路径模式映射 - 对应Java版本的urlPath
	urlPatterns := map[string]string{
		`^/user/.+/.+$`:            "2",
		`^/project/.+/task/.+/.+$`: "2,4",
		`^/project/.+/.+$`:         "2",
		`^/dashboard/.+/.+$`:       "4",
	}

	// 匹配URL模式
	for pattern, positions := range urlPatterns {
		matched, _ := regexp.MatchString(pattern, path)
		if matched {
			pathSegments := strings.Split(path, "/")
			var result strings.Builder

			positionStrs := strings.Split(positions, ",")
			for _, posStr := range positionStrs {
				pos, err := strconv.Atoi(posStr)
				if err == nil && pos < len(pathSegments) {
					result.WriteString("&")
					result.WriteString(pathSegments[pos])
				}
			}
			return result.String()
		}
	}

	return ""
}

func BuildV2Header(params map[string]interface{}, accessKey, accusesSecret string, path []string) map[string]string {
	headers := map[string]string{
		"accessKey":      accessKey,
		"x-cs-timestamp": strconv.FormatInt(time.Now().Add(5*time.Minute).UnixMilli(), 10),
		"x-cs-nonce":     uuid.New().String(),
	}
	pa := strings.Join(path, "&")

	// 处理请求体参数
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ss := make([]string, 0)
	for _, k := range keys {
		ss = append(ss, fmt.Sprintf("%s=%v", k, params[k]))
	}

	data1 := strings.Join(ss, "&")

	// 构建签名数据
	end := fmt.Sprintf("%s&%s&%s&%s&%s",
		data1,
		pa,
		accusesSecret,
		headers["x-cs-timestamp"],
		headers["x-cs-nonce"],
	)

	end = strings.ReplaceAll(end, "&&", "&")
	for strings.HasPrefix(end, "&") {
		end = end[1:]
	}
	for strings.HasSuffix(end, "&") {
		end = end[:len(end)-1]
	}
	if len(data1) == 0 && len(pa) == 0 {
		end = "&" + end
	}

	// 计算SHA256签名
	hash := sha256.Sum256([]byte(end))
	signature := hex.EncodeToString(hash[:])
	headers["x-cs-signature"] = signature

	return headers
}

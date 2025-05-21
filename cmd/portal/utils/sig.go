package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

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

	fmt.Printf("签名数据: %s\n", end)

	// 计算SHA256签名
	hash := sha256.Sum256([]byte(end))
	signature := hex.EncodeToString(hash[:])
	headers["x-cs-signature"] = signature

	return headers
}

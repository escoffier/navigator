package util

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func GetInt64SliceFromQuery(ctx *gin.Context, key string) []int64 {
	values := make([]int64, 0)
	statusStr := ctx.Query(key)
	if statusStr != "" {
		split := strings.Split(statusStr, ",")
		for i := range split {
			parseInt, err := strconv.ParseInt(split[i], 10, 64)
			if err != nil {
				logging.GetLogger().Err(err).Str("param", split[i]).Msgf("get %s param", key)
				continue
			}
			values = append(values, parseInt)
		}
	}

	return DuplicateInt64Slice(values)
}

func GetStringSliceFromQuery(ctx *gin.Context, key string) []string {
	res := make([]string, 0)
	statusStr := ctx.Query(key)
	split := strings.Split(statusStr, ",")
	for i := range split {
		if split[i] != "" {
			res = append(res, split[i])
		}
	}
	return DuplicateStringSlice(res)
}

// 从gin的query中取值后解析成int64,如果没有传或解析出错，都是返回0
func GetInt64FromQuery(ctx *gin.Context, key string) int64 {
	var value int64
	keyStr := ctx.Query(key)
	if keyStr != "" {
		parseInt, err := strconv.ParseInt(keyStr, 10, 64)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get %s param", key)
		}
		value = parseInt
	}
	return value
}

// 从gin的query中取值后解析成uint64,如果没有传或解析出错，都是返回0
func GetUint64FromQuery(ctx *gin.Context, key string) uint64 {
	var value uint64
	keyStr := ctx.Query(key)
	if keyStr != "" {
		parseInt, err := strconv.ParseUint(keyStr, 10, 64)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get %s param", key)
		}
		value = parseInt
	}
	return value
}

// 从gin的query中取值后解析成y或n, 如果即传了y又传了n，就认为没有传
func GetYesOrNoFromQuery(ctx *gin.Context, key string) string {
	split := strings.Split(ctx.Query(key), ",")
	if len(split) == 1 {
		if split[0] == "y" {
			return "y"
		}
		if split[0] == "n" {
			return "n"
		}
	}
	return ""
}

// 从gin的query中取值后解析成 true和false,如果即传了true又传了false，就认为没有传
func GetBoolStringFromQuery(ctx *gin.Context, key string) string {
	split := strings.Split(ctx.Query(key), ",")
	if len(split) == 1 {
		if split[0] == "true" {
			return "true"
		}
		if split[0] == "false" {
			return "false"
		}
	}
	return ""
}

func GetKeywordFromQuery(ctx *gin.Context, key string) string {
	word := ctx.Query(key)
	return strings.TrimSpace(word)
}

func GetLanguage(ctx *gin.Context) string {
	if strings.ToLower(ctx.GetHeader("Accept-Language")) == "en" ||
		strings.ToLower(ctx.GetHeader("accept-language")) == "en" {
		return "en"
	}
	return "zh"
}

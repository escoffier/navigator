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
				logging.GetLogger().Err(err).Msgf("get %s param", key)
				continue
			}
			values = append(values, parseInt)
		}
	}

	return DeDuplicationInt64Slice(values)
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

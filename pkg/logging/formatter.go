package logging

import (
	"fmt"
	"path/filepath"
)

// OnlyLogFileNameFormat 打印日志时只打印文件名
func OnlyLogFileNameFormat(i interface{}) string {
	c, ok := i.(string)
	if !ok {
		return fmt.Sprintf("%s", i)
	}
	_, filename := filepath.Split(c)
	return filename
}

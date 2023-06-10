package scani18

import (
	"fmt"
	"net/http"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func CreateSensitiveRule(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	vi := &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "创建敏感文件规则失败",
		En:   "create sensitive file rule fail",
	}

	if err != nil && strings.Contains(err.Error(), consts.DuplicateKey) {
		vi.Ch = fmt.Sprintf("已存在相同名字的敏感文件规则")
		vi.En = fmt.Sprintf("the same sensitive file rule already exists")
		return vi
	}
	return vi
}

func SearchSensitiveRule(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询敏感文件规则失败",
		En:   "search sensitive file rule fail",
	}
}

func UpdateSensitiveRule(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新敏感文件规则失败",
		En:   "update sensitive file rule fail",
	}
}

func DeleteSensitiveRule(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "删除敏感文件规则失败",
		En:   "delete sensitive file rule fail",
	}
}

func CreateScanImageConfig(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	vi := &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "创建扫描配置出错",
		En:   "create scan config fail",
	}

	if err != nil && strings.Contains(err.Error(), consts.DuplicateKey) {
		vi.Ch = fmt.Sprintf("已存在相同配置")
		vi.En = fmt.Sprintf("the config already exists")
		return vi
	}
	return vi

}

func UpdateScanImageConfig(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新镜像配置出错",
		En:   "update image config fail",
	}
}

func GetScanImageConfig(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "获取镜像配置出错",
		En:   "get image config fail",
	}
}

func NotConfigID() *i18.ErrI18 {

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未获取到ID",
		En:   "not get config ID",
	}
}

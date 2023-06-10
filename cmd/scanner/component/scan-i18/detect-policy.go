package scani18

import (
	"fmt"
	"net/http"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func UpdatePolicy(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新检测策略出错",
		En:   "update detect policy fail",
	}
}

func DeletePolicy(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "删除检测策略出错",
		En:   "update detect policy fail",
	}
}

func GetPolicy(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "获取检测策略详情出错",
		En:   "get detect policy fail",
	}
}

func NotGetPolicyID() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未获取到策略ID",
		En:   "not get policy ID",
	}
}

func SearchPolicy(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询检测策略出错",
		En:   "search detect policy fail",
	}
}

func CreatePolicy(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}

	vi := &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "创建检测策略失败",
		En:   "create detect policy fail",
	}

	if err != nil && strings.Contains(err.Error(), consts.DuplicateKey) {
		vi.Ch = fmt.Sprintf("已存在相同名字的检测策略")
		vi.En = fmt.Sprintf("the same detect policy already exists")
		return vi
	}
	return vi
}

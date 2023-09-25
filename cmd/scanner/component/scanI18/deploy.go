package scani18

import (
	"fmt"
	"net/http"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func SearchDeployRecord(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询阻断记录出错",
		En:   "search deploy record fail",
	}
}

func CreatDeployRecord(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "创建阻断记录出错",
		En:   "create deploy record fail",
	}
}

func SearchWhiteImage(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询镜像白名单出错",
		En:   "search white image fail",
	}
}

func DeleteWhiteImage(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "删除镜像白名单出错",
		En:   "delete white image fail",
	}
}

func CreateWhiteImage(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	vi := &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "创建镜像白名单出错",
		En:   "create white image fail",
	}

	if err != nil && strings.Contains(err.Error(), consts.DuplicateKey) {
		vi.Ch = fmt.Sprintf("已存在相同名字的白名单")
		vi.En = fmt.Sprintf("the same white image already exists")
		return vi
	}

	return vi

}

func UpdateWhiteImage(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	vi := &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新镜像白名单",
		En:   "update white image fail",
	}
	if err != nil && strings.Contains(err.Error(), consts.DuplicateKey) {
		vi.Ch = fmt.Sprintf("已存在相同名字的白名单")
		vi.En = fmt.Sprintf("the same white image already exists")
		return vi
	}

	return vi
}

func NotGetID() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未获取ID",
		En:   "not get ID",
	}
}

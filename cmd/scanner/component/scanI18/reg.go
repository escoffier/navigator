package scani18

import (
	"fmt"
	"net/http"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func DeleteReg(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "删除仓库失败",
		En:   "delete registry fail",
	}
}

func SearchReg(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "获取仓库信息失败",
		En:   "search registry fail",
	}
}

func NotGetRegID() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  fmt.Errorf("not get registrty ID"),
		Ch:   "未获取到仓库ID",
		En:   "not get registry ID",
	}
}

func RegTypeErr() error {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  fmt.Errorf("unsupported repository type"),
		Ch:   "不支持的仓库类型",
		En:   "unsupported repository type",
	}

}

func ValidateReg(err error) *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "尝试连接仓库失败",
		En:   "can not validate registry info",
	}
}

func CreateRegistry(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	vi := &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "新建仓库失败",
		En:   "create registry fail",
	}

	if err != nil && strings.Contains(err.Error(), consts.DuplicateKey) {
		vi.Ch = fmt.Sprintf("仓库名称重复")
		vi.En = fmt.Sprintf("the same registry already exists")
		return vi
	}
	return vi
}

func UpdateRegistry(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	vi := &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新仓库失败",
		En:   "update registry fail",
	}

	if err != nil && strings.Contains(err.Error(), consts.DuplicateKey) {
		vi.Ch = fmt.Sprintf("仓库名称重复")
		vi.En = fmt.Sprintf("the same registry already exists")
		return vi
	}
	return vi
}

func ConnectRPC() *i18.ErrI18 {

	vi := &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "连接子集群失败",
		En:   "connect sub scanner",
	}

	return vi
}

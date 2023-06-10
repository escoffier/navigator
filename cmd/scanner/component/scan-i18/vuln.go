package scani18

import (
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func SearchVuln(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询漏洞失败",
		En:   "search vulnerability  fail",
	}
}

func GetVulnInfo(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询漏洞信息失败",
		En:   "get vulnerability info fail",
	}
}

func NotGetVulnID() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未获取漏洞ID",
		En:   "get vulnerability ID",
	}
}

func NotGetVuln() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未查询到漏洞",
		En:   "not get vulnerability",
	}
}

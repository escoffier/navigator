package scani18

import (
	"fmt"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func SearchVuln(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询漏洞失败",
		En:   "search vulnerability  fail",
	}
}

func SearchPKG(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询软件包失败",
		En:   "search pkg fail",
	}
}

func GetVulnInfo(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
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

func GetLicenseInfo(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询License失败",
		En:   "get License info fail",
	}
}

func GetSensitiveInfo(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询敏感文件失败",
		En:   "get sensitive file info fail",
	}
}

func GetMalwareInfo(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询病毒失败",
		En:   "get malware info fail",
	}
}

func NotGetLicenseInfo() *i18.ErrI18 {

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  fmt.Errorf("not get license info"),
		Ch:   "未查询到 LICENCE 信息",
		En:   "get License info fail",
	}
}

package scani18

import (
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func NotGetWebshell() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未查询到webshell",
		En:   "not get webshell",
	}
}

func ParameterErr(err error) *i18.ErrI18 {

	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}

	return i18.CreateI18BadReqErr("参数不正确", "parameter is incorrect")
}

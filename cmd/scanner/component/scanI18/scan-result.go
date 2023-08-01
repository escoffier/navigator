package scani18

import (
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func NotGetFile(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "未查询到文件,文件已清理或未上传",
		En:   "not get file,file was cleaned or not uploaded",
	}
}

func ParameterErr(err error) *i18.ErrI18 {

	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return i18.CreateI18BadReqErr("参数不正确", "parameter is incorrect")
}

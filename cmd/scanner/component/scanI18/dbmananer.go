package scani18

import (
	"errors"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func ParseDbFileErr(err error) *i18.ErrI18 {
	var e1 *i18.ErrI18
	if errors.As(err, &e1) {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "解析 db 文件出错",
		En:   "parse db file error",
	}
}

func SaveDbFileErr(err error) *i18.ErrI18 {
	var e1 *i18.ErrI18
	if errors.As(err, &e1) {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "保存 db 文件出错",
		En:   "save db file error",
	}
}

func UpdateDbFileErr(err error) *i18.ErrI18 {
	var e1 *i18.ErrI18
	if errors.As(err, &e1) {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新 db 文件出错",
		En:   "update db file error",
	}
}

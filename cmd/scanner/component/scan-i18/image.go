package scani18

import (
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func NotGetImage() *i18.ErrI18 {

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未查询到镜像",
		En:   "not get image",
	}
}

func NotGetImageID() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未获取到镜像ID",
		En:   "not get image ID",
	}
}

func SearchImage(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询镜像失败",
		En:   "search image fail",
	}
}

func GetImageInfo(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询镜像信息失败",
		En:   "get image info fail",
	}
}

func SearchImageLayer(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询镜像层级信息失败",
		En:   "search image layer fail",
	}
}

func UpdateImage(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新镜像信息失败",
		En:   "update image fail",
	}
}

func DeleteBaseImage(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "基础镜像更新应用失败",
		En:   "update image to app image fail",
	}
}

func SearchNode(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "获取节点信息失败",
		En:   "search node info fail",
	}
}

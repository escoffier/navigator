package scani18

import (
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func NotGetScanTaskID() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未获取到扫描任务ID",
		En:   "not get scan task ID",
	}
}

func NotGetScanSubtaskID() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未获取到扫描子任务ID",
		En:   "not get scan subtask ID",
	}
}

func NotGetScanTask() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未查询到扫描任务",
		En:   "not get scan task",
	}
}

func NotGetScanSubtask() *i18.ErrI18 {
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Ch:   "未查询到扫描子任务",
		En:   "not get scan subtask",
	}
}

func CreateScanTask(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "新建扫描任务失败",
		En:   "create scan task fail",
	}
}

func SearchScanTask(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询扫描任务失败",
		En:   "search scan task fail",
	}
}

func SearchScanSubtask(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询扫描子任务失败",
		En:   "search scan subtask fail",
	}
}

func UpdateScanTask(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新扫描任务失败",
		En:   "update scan task fail",
	}
}

func UpdateScanSubtask(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	if e1, ok := err.(i18.ErrI18); ok {
		return &e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "重新调度扫描子任务失败",
		En:   "update scan subtask fail",
	}
}

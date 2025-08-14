package portalI18

import (
	"errors"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
)

func NotCorrectPwd(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}

	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "密码不正确",
		En:   "password is not correct",
	}
}

func NotHasPermission(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "没有权限",
		En:   "not has permission",
	}
}

func UserUsernameExit(err error) *i18.ErrI18 {
	var e1 *i18.ErrI18
	if errors.As(err, &e1) {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "用户名已存在",
		En:   "user name is exist",
	}
}

func UserEmailExit(err error) *i18.ErrI18 {
	var e1 *i18.ErrI18
	if errors.As(err, &e1) {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "邮箱已存在",
		En:   "user email is exist",
	}
}

// 同名项目已存在
func ProjectExit(err error) *i18.ErrI18 {
	var e1 *i18.ErrI18
	if errors.As(err, &e1) {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "同名项目已存在",
		En:   "project is exist",
	}
}

// 查询用户
func SearchUserFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询用户失败",
		En:   "search user fail",
	}
}

func NotGetUser(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "未获取到用户",
		En:   "not get user",
	}
}

func LoginFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "登录失败",
		En:   "login fail",
	}
}

// 未登录
func NotLogin(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "未登录",
		En:   "not login",
	}
}

// 更新用户失败
func UpdateUserFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新用户失败",
		En:   "update user fail",
	}
}

// 删除用户失败
func DeleteUserFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "删除用户失败",
		En:   "delete user fail",
	}
}

// 更新项目失败
func UpdateProjectFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "更新项目失败",
		En:   "update project fail",
	}
}

// 删除项目失败
func DeleteProjectFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "删除项目失败",
		En:   "delete project fail",
	}
}

// 项目不存在
func ProjectNotExist(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "项目不存在",
		En:   "project not exist",
	}
}

// 查询项目失败
func SearchProjectFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询项目失败",
		En:   "search project fail",
	}
}

// 创建项目失败
func CreateProjectFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "创建项目失败",
		En:   "create project fail",
	}
}

// ===== CodeSec相关错误 =====

// 获取扫描结果失败
func GetScanResultFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "获取扫描结果失败",
		En:   "get scan result fail",
	}
}

// 获取漏洞列表失败
func GetVulnListFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "获取漏洞列表失败",
		En:   "get vulnerability list fail",
	}
}

// 创建漏洞记录失败
func CreateVulnFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "创建漏洞记录失败",
		En:   "create vulnerability record fail",
	}
}

// 查询漏洞记录失败
func SearchVulnFail(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "查询漏洞记录失败",
		En:   "search vulnerability record fail",
	}
}

// 漏洞记录不存在
func VulnNotExist(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "漏洞记录不存在",
		En:   "vulnerability record not exist",
	}
}

// 扫描结果不存在
func ScanResultNotExist(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "扫描结果不存在",
		En:   "scan result not exist",
	}
}

// 项目UUID参数错误
func ProjectUuidRequired(err error) *i18.ErrI18 {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "项目UUID参数是必需的",
		En:   "project UUID parameter is required",
	}
}

func ScanProjectFail(err error) error {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "扫描项目失败",
		En:   "scan project fail",
	}

}

func ProjectIDRequired(err error) error {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "项目ID参数是必需的",
		En:   "project ID parameter is required",
	}
}

func ScanTypeRequired(err error) error {
	if e1, ok := err.(*i18.ErrI18); ok {
		return e1
	}
	return &i18.ErrI18{
		Code: http.StatusBadRequest,
		Err:  err,
		Ch:   "扫描类型参数是必需的",
		En:   "scan type parameter is required",
	}
}

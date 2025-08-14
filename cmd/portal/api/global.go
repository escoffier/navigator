package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type GlobalHandler struct {
}

func NewGlobalHandler() *GlobalHandler {
	return &GlobalHandler{}
}

// getProjectTypeConst 获取项目类型常量
func (s *GlobalHandler) getProjectTypeConst() []imagesec.LabelValue {
	res := make([]imagesec.LabelValue, 0)
	res = append(res, imagesec.LabelValue{Label: "GitHub", Value: model.GitTypeGitHub})
	res = append(res, imagesec.LabelValue{Label: "GitLabV4", Value: model.GitTypeGitlabV4})
	res = append(res, imagesec.LabelValue{Label: "GitLabV3", Value: model.GitTypeGitlabV3})
	res = append(res, imagesec.LabelValue{Label: "Gitee", Value: model.GitTypeGitee})
	return res
}

// getUserRoleConst 获取用户角色常量
func (s *GlobalHandler) getUserRoleConst() []imagesec.LabelValue {
	res := make([]imagesec.LabelValue, 0)
	res = append(res, imagesec.LabelValue{Label: "管理员", Value: model.UserRoleAdmin})
	res = append(res, imagesec.LabelValue{Label: "普通用户", Value: model.UserRoleOperator})
	return res
}

// getScanStatusConst 获取扫描状态常量
func (s *GlobalHandler) getScanStatusConst() []imagesec.LabelValue {
	res := make([]imagesec.LabelValue, 0)
	res = append(res, imagesec.LabelValue{Label: "未扫描", Value: "not_scan"})
	res = append(res, imagesec.LabelValue{Label: "扫描中", Value: "scanning"})
	res = append(res, imagesec.LabelValue{Label: "扫描成功", Value: "success"})
	res = append(res, imagesec.LabelValue{Label: "扫描失败", Value: "failed"})
	return res
}

// getSeverityConst 获取风险等级常量
func (s *GlobalHandler) getSeverityConst() []imagesec.LabelValue {
	res := make([]imagesec.LabelValue, 0)
	res = append(res, imagesec.LabelValue{Label: model.SeverityCriticalView, Value: model.SeverityCritical})
	res = append(res, imagesec.LabelValue{Label: model.SeverityHighView, Value: model.SeverityHigh})
	res = append(res, imagesec.LabelValue{Label: model.SeverityMediumView, Value: model.SeverityMedium})
	res = append(res, imagesec.LabelValue{Label: model.SeverityLowView, Value: model.SeverityLow})
	res = append(res, imagesec.LabelValue{Label: model.SeverityOtherView, Value: model.SeverityOther})
	res = append(res, imagesec.LabelValue{Label: model.SeverityUnRiskView, Value: model.SeverityUnRisk})
	return res
}

// getUserStatusConst 获取用户状态常量
func (s *GlobalHandler) getUserStatusConst() []imagesec.LabelValue {
	res := make([]imagesec.LabelValue, 0)
	res = append(res, imagesec.LabelValue{Label: "启用", Value: model.UserStatusActive})
	res = append(res, imagesec.LabelValue{Label: "停用", Value: model.UserStatusInactive})
	res = append(res, imagesec.LabelValue{Label: "锁定", Value: model.UserStatusLocked})
	return res
}

// getRiskLevelConst 获取项目风险级别常量
func (s *GlobalHandler) getRiskLevelConst() []imagesec.LabelValue {
	res := make([]imagesec.LabelValue, 0)
	res = append(res, imagesec.LabelValue{Label: "超危", Value: model.SeverityCritical})
	res = append(res, imagesec.LabelValue{Label: "高", Value: model.SeverityHigh})
	res = append(res, imagesec.LabelValue{Label: "中", Value: model.SeverityMedium})
	res = append(res, imagesec.LabelValue{Label: "低", Value: model.SeverityLow})
	return res
}

func (s *GlobalHandler) getExportTaskStatusConst() []imagesec.LabelValue {
	res := make([]imagesec.LabelValue, 0)
	res = append(res, imagesec.LabelValue{Label: "未开始", Value: "pending"})
	res = append(res, imagesec.LabelValue{Label: "进行中", Value: "running"})
	res = append(res, imagesec.LabelValue{Label: "已完成", Value: "finished"})
	res = append(res, imagesec.LabelValue{Label: "导出出错", Value: "error"})
	return res
}

func (s *GlobalHandler) GetConst(ctx *gin.Context) {
	tye := util.GetKeywordFromQuery(ctx, "type")

	// 如果没有指定类型，返回全部常量
	if tye == "" {
		allConsts := map[string][]imagesec.LabelValue{
			"projectType":      s.getProjectTypeConst(),
			"userRole":         s.getUserRoleConst(),
			"scanStatus":       s.getScanStatusConst(),
			"severity":         s.getSeverityConst(),
			"userStatus":       s.getUserStatusConst(),
			"riskLevel":        s.getRiskLevelConst(),
			"exportTaskStatus": s.getExportTaskStatusConst(),
		}
		response.JSONOK(ctx, response.WithItem(allConsts))
		return
	}

	// 根据指定类型返回对应常量
	switch tye {
	case "projectType":
		response.JSONOK(ctx, response.WithItems(s.getProjectTypeConst()))
	case "userRole":
		response.JSONOK(ctx, response.WithItems(s.getUserRoleConst()))
	case "scanStatus":
		response.JSONOK(ctx, response.WithItems(s.getScanStatusConst()))
	case "severity":
		response.JSONOK(ctx, response.WithItems(s.getSeverityConst()))
	case "userStatus":
		response.JSONOK(ctx, response.WithItems(s.getUserStatusConst()))
	case "riskLevel":
		response.JSONOK(ctx, response.WithItems(s.getRiskLevelConst()))
	case "exportTaskStatus":
		response.JSONOK(ctx, response.WithItems(s.getExportTaskStatusConst()))
	default:
		response.JSONError(ctx, fmt.Errorf("not get consts"))
	}
}

package api

import (
	"github.com/gin-gonic/gin"
	model "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type GlobalHandler struct {
}

func NewGlobalHandler() *GlobalHandler {
	return &GlobalHandler{}
}

func (s *GlobalHandler) GetConst(ctx *gin.Context) {
	tye := util.GetKeywordFromQuery(ctx, "type")
	if tye == "projectType" {
		// 项目类型
		res := make([]imagesec.LabelValue, 0)
		res = append(res, imagesec.LabelValue{Label: "GitHub", Value: model.GitTypeGitHub})
		res = append(res, imagesec.LabelValue{Label: "GitLabV4", Value: model.GitTypeGitlabV4})
		res = append(res, imagesec.LabelValue{Label: "GitLabV3", Value: model.GitTypeGitlabV3})
		res = append(res, imagesec.LabelValue{Label: "Getee", Value: model.GitTypeGitee})
		response.JSONOK(ctx, response.WithItems(res))
	}
	if tye == "userRole" {
		// 用户角色
		res := make([]imagesec.LabelValue, 0)
		res = append(res, imagesec.LabelValue{Label: "管理员", Value: model.UserRoleAdmin})
		res = append(res, imagesec.LabelValue{Label: "普通用户", Value: model.UserRoleOperator})
		response.JSONOK(ctx, response.WithItems(res))
	}
}

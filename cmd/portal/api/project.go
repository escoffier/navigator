package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ProjectHandler struct {
	service service.ProjectService
}

func NewProjectHandler(service service.ProjectService) *ProjectHandler {
	return &ProjectHandler{service: service}
}
func (h *ProjectHandler) GetProjects(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	param := model.SearchProjectParam{ID: id}
	if id <= 0 {
		response.JSONError(ctx, fmt.Errorf("id is required"))
		return
	}
	projects, _, err := h.service.SearchProject(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(projects) == 0 {
		response.JSONError(ctx, fmt.Errorf("project not found"))
		return
	}

	// 转换为API结构体
	apiProject := &Project{}
	apiProject.FromModel(projects[0])
	response.JSONOK(ctx, response.WithItem(apiProject))
}

func (h *ProjectHandler) SearchProjects(ctx *gin.Context) {
	name := util.GetKeywordFromQuery(ctx, "name")
	url := util.GetKeywordFromQuery(ctx, "url")
	gitType := util.GetStringSliceFromQuery(ctx, "gitType")
	riskLevel := util.GetStringSliceFromQuery(ctx, "riskLevel")

	param := model.SearchProjectParam{
		Name:      name,
		GitType:   gitType,
		Url:       url,
		RiskLevel: riskLevel,
		Filter:    imagesecModel.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit).SetSortFiled("created_at").SetSortDesc(),
	}

	projects, cnt, err := h.service.SearchProject(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	// 转换为API结构体列表项
	apiProjects := make([]*Project, len(projects))
	for i, project := range projects {
		apiProjects[i] = apiProjects[i].FromModel(project)
	}

	response.JSONOK(ctx, response.WithItems(projects),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}

// CreateProject 创建项目接口
func (h *ProjectHandler) CreateProject(ctx *gin.Context) {
	req := &model.Project{}
	if err := ctx.ShouldBindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	if err := h.service.CreateProject(ctx, req); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

func (h *ProjectHandler) UpdateProject(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")

	req := model.Project{}
	if err := ctx.ShouldBindJSON(&req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	if err := h.service.UpdateProject(ctx, id, &req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItem(req))
}

func (h *ProjectHandler) DeleteProject(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	ids := util.GetInt64SliceFromQuery(ctx, "ids")
	ids = append(ids, id)
	ids = util.DuplicateInt64Slice(ids)
	for _, id := range ids {
		if err := h.service.DeleteProject(ctx, id); err != nil {
			response.JSONError(ctx, err)
			return
		}
	}
	response.JSONOK(ctx)
}

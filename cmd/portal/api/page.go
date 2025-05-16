package api

import (
	"fmt"
	"sort"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/codesec"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/sourceCheck"
	"gitlab.com/piccolo_su/vegeta/cmd/portal/component/token"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type HomePageHandler struct {
	sourceCheckRUL string
	codesecUrl     string
}

func NewHomePageHandler(sourceCheckRUL string, codesecUrl string) *HomePageHandler {
	s := &HomePageHandler{sourceCheckRUL: sourceCheckRUL, codesecUrl: codesecUrl}
	return s
}

// GetHighRiskComponents 高危组件TOP10
func (s *HomePageHandler) GetHighRiskComponents(ctx *gin.Context) {
	p := token.GetPayload(ctx)
	api1 := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL), sourceCheck.WithAuthorization(p.SourceCheckToken))
	param := sourceCheck.StatisticsRequest{ProjectFlag: s.GetSourceCheckProject(ctx)}
	res, err := api1.GetHighRiskComponents(ctx, param)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("调用sourceCheck接口失败:%v", err))
		return
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Grade > res[j].Grade
	})
	response.JSONOK(ctx, response.WithItems(res))
}

// GetMostUsedComponents 被引用次数最多的组件
func (s *HomePageHandler) GetMostUsedComponents(ctx *gin.Context) {
	p := token.GetPayload(ctx)
	api1 := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL), sourceCheck.WithAuthorization(p.SourceCheckToken))
	param := sourceCheck.StatisticsRequest{ProjectFlag: s.GetSourceCheckProject(ctx)}
	res, err := api1.GetMostUsedComponents(ctx, param)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("调用sourceCheck接口失败:%v", err))
		return
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Count > res[j].Count
	})

	response.JSONOK(ctx, response.WithItems(res))
}

// GetLicenseStatistics 许可分布
func (s *HomePageHandler) GetLicenseStatistics(ctx *gin.Context) {
	p := token.GetPayload(ctx)
	api1 := sourceCheck.NewApi(sourceCheck.WithBaseURL(s.sourceCheckRUL), sourceCheck.WithAuthorization(p.SourceCheckToken))
	param := sourceCheck.StatisticsRequest{ProjectFlag: s.GetSourceCheckProject(ctx)}
	res, err := api1.GetLicenseStatistics(ctx, param)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("调用sourceCheck接口失败:%v", err))
		return
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Value > res[j].Value
	})
	response.JSONOK(ctx, response.WithItems(res))
}

func (s *HomePageHandler) CountVulStatistics(ctx *gin.Context) {
	p := token.GetPayload(ctx)

	param := codesec.DashboardParam{
		AccessKey:    p.CodesecKey,
		AccessSecret: p.CodesecSecret,
	}

	res, err := codesec.CountVulStatistics(s.codesecUrl, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(res))
}

func (s *HomePageHandler) LanguageTop5Statistics(ctx *gin.Context) {

	p := token.GetPayload(ctx)

	param := codesec.DashboardParam{
		AccessKey:    p.CodesecKey,
		AccessSecret: p.CodesecSecret,
	}

	res, err := codesec.LanguageTop5Statistics(s.codesecUrl, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

func (s *HomePageHandler) VulTypeTop5Statistics(ctx *gin.Context) {

	p := token.GetPayload(ctx)

	param := codesec.DashboardParam{
		AccessKey:    p.CodesecKey,
		AccessSecret: p.CodesecSecret,
	}

	res, err := codesec.VulTypeTop5Statistics(s.codesecUrl, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

func (s *HomePageHandler) GetSourceCheckProject(ctx *gin.Context) string {
	return "ALL"
	// p := token.GetPayload(ctx)
	// if p.Role == model.UserRoleAdmin {
	// 	return "ALL" // 管理员查看所有项目
	// }
	// return "IN" // 查自已团队
}

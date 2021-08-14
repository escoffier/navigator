package api

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type RejectApi struct {
	Srv component.ImageRejectSrv
}

func (s *RejectApi) DeletePolicy(ctx *gin.Context) {
	id, _ := strconv.ParseInt(ctx.Param("id"), 10, 64)
	s.Srv.DeletePolicy(ctx, id)
	response.JSONOK(ctx)
}

func (s *RejectApi) Overview(ctx *gin.Context) {
	graph := ctx.Query("graph")
	overview, err := s.Srv.GetOverview(ctx, graph)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*overview))
}

func (s *RejectApi) ListRejectRecord(ctx *gin.Context) {
	search := ctx.Query("search")
	filter := model.GetFilter(ctx)
	libraries := make([]string, 0)
	library := ctx.Query("library")
	if library != "" {
		libraries = append(libraries, strings.Split(library, ",")...)
	}
	rejectReason := strings.Split(ctx.Query("reject_reason"), ",")
	rjr := make([]int64, 0)
	for _, rr := range rejectReason {
		if i, err := strconv.ParseInt(rr, 10, 64); err == nil {
			rjr = append(rjr, i)
		}
	}
	// 默认只以阻断时间排序
	if filter.SortFiled == "" {
		filter.SortFiled = "reject_at"
	}
	filter = filter.SetDefault()

	rgs, cnt, err := s.Srv.ListRejectRecord(ctx, search, libraries, rjr, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(rgs),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *RejectApi) ListWhitelist(ctx *gin.Context) {
	search := ctx.Query("search")
	filter := model.GetFilter(ctx)
	iws, cnt, err := s.Srv.ListImageWhitelist(ctx, search, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(iws),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *RejectApi) DeleteWhitelist(ctx *gin.Context) {
	id, _ := strconv.ParseInt(ctx.Param("id"), 10, 64)
	err := s.Srv.DeleteImageWhitelist(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

func (s *RejectApi) CreateWhitelist(ctx *gin.Context) {
	wi := new(model.ImageWhitelist)
	if err := ctx.BindJSON(wi); err != nil {
		response.JSONError(ctx, errors.New(fmt.Sprintf("解析传参出错：%s", err.Error())))
		return
	}
	res, err := s.Srv.CreateImageWhitelist(ctx, wi.FullRepoName, wi.Library, wi.Tag, wi.Digest)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
}

func NewRejectApiSrv(srv component.ImageRejectSrv) *RejectApi {
	return &RejectApi{
		Srv: srv,
	}
}

package api

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type RegistrySrv struct {
	RegistrySrv component.RegistrySrvInterface
	RejectSrv   component.ImageRejectSrv
}

func NewRegistrySrv(registrySrv component.RegistrySrvInterface, rejectSrv component.ImageRejectSrv) *RegistrySrv {
	return &RegistrySrv{RegistrySrv: registrySrv, RejectSrv: rejectSrv}
}

// UpdateRegistry
// @Summary 更新仓库信息
// @Title 更新仓库信息
// @Author guolingkai@tensorsecurity.cn
// @Description 更新仓库信息
// @Tags registry
// @Param id path int true "仓库类型"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/register/registry/:id [put]
func (s *RegistrySrv) UpdateRegistry(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, errors.New("仓库ID不正确"))
		return
	}

	reg := new(model.Registry)
	if err := ctx.BindJSON(reg); err != nil {
		logging.GetLogger().Error().Err(err).Msg("UpdateRegistry序列化数据出错")
		response.JSONError(ctx, err)
		return
	}
	err = s.RegistrySrv.UpdateRegistry(ctx, id, *reg)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

// CreateRegistry
// @Summary 创建仓库信息
// @Title 创建仓库信息
// @Author guolingkai@tensorsecurity.cn
// @Description 创建仓库信息
// @Tags registry
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/register/registry [post]
func (s *RegistrySrv) CreateRegistry(ctx *gin.Context) {
	reg := new(model.Registry)
	if err := ctx.BindJSON(reg); err != nil {
		logging.GetLogger().Error().Err(err).Msg("CreateRegistry序列化数据出错")
		response.JSONError(ctx, err)
		return
	}
	reg.UseType = model.RegistryUseTypeNormal
	_, err := s.RegistrySrv.CreateRegistry(ctx, *reg)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

// DeleteRegistry
// @Summary 删除仓库信息
// @Title 删除仓库信息
// @Author guolingkai@tensorsecurity.cn
// @Description 删除仓库信息
// @Tags registry
// @Param id path int true "仓库类型"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/register/registry/:id [delete]
func (s *RegistrySrv) DeleteRegistry(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, errors.New("仓库ID不正确"))
		return
	}

	if err := s.RegistrySrv.DeleteRegistry(ctx, id); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

// GetRegistryType
// @Summary 仓库类型列表
// @Title 仓库类型列表
// @Author guolingkai@tensorsecurity.cn
// @Description 仓库类型列表
// @Tags registry
// @Param id path int true "仓库类型"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/register/reg-type [get]
func (s *RegistrySrv) GetRegistryType(ctx *gin.Context) {

	ans, err := s.RegistrySrv.GetRegistryType(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(ans))
}

// SearchRegistry
// @Summary 获取仓库列表
// @Title 获取仓库列表
// @Author guolingkai@tensorsecurity.cn
// @Description 获取registry列表信息
// @Tags registry
// @Param no_policy query bool true "是否需要配置策略的仓库"
// @Success 200 {object} ApiWithItem{data=ApiItem{items=[]model.Registry{}}}
// @Router	/api/v1/register/registries [get]
func (s *RegistrySrv) SearchRegistry(ctx *gin.Context) {
	useType, _ := strconv.ParseInt(ctx.Query("usetype"), 10, 64)
	search := ctx.Query("search")

	regType := ctx.Query("reg_type")
	filter := model.GetFilter(ctx)
	if useType <= 0 {
		useType = model.RegistryUseTypeNormal
	}
	param := component.SearchRegistryParam{Search: search, UseType: useType}
	if regType != "" {
		param.RegType = strings.Split(strings.Replace(regType, " ", "", -1), ",")
	}

	registries, cnt, err := s.RegistrySrv.SearchRegistry(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	regMap := make(map[string]bool)
	for i := range registries {
		regMap[registries[i].Url] = true
	}

	ans := make([]model.Registry, 0)

	for i := range registries {
		if regMap[registries[i].Url] {
			ans = append(ans, registries[i])
		}
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// GetRegistry
// @Summary 获取指定仓库的具体信息
// @Title 获取指定仓库的具体信息
// @Author guolingkai@tensorsecurity.cn
// @Description 获取registry具体信息
// @Tags registry
// @Param usetype query string true "仓库类型"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.Registry{}}}
// @Router	/api/v1/register/registry [get]
func (s *RegistrySrv) GetRegistry(ctx *gin.Context) {
	id, _ := strconv.ParseInt(ctx.Param("id"), 10, 64)

	reg, err := s.RegistrySrv.GetRegistry(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*reg))
}

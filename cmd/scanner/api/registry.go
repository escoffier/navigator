package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
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
		logging.GetLogger().Err(err).Msg("UpdateRegistry序列化数据出错")
		response.JSONError(ctx, err)
		return
	}
	if reg.ScannerInstance == "" {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get scanner_instance")))
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
	reg := model.Registry{}
	if err := ctx.BindJSON(&reg); err != nil {
		logging.GetLogger().Err(err).Msg("CreateRegistry序列化数据出错")
		response.JSONError(ctx, err)
		return
	}
	if reg.ScannerInstance == "" {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get scanner_instance")))
		return
	}
	reg.UseType = model.UserRegistry
	_, err := s.RegistrySrv.CreateRegistry(ctx, reg)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: reg.Name,
		ID:   strconv.FormatInt(reg.ID, 10),
		Link: "api/v2/containerSec/scanner/register/registry",
	}))
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
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: fmt.Sprintf("Registry %d", id),
		ID:   strconv.Itoa(int(id)),
		Link: "api/v2/containerSec/scanner/register/registry/" + strconv.Itoa(int(id)),
	}))
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

// @Summary 地域节点信息
// @Title 地域节点信息
// @Author liuqiang@tensorsecurity.cn
// @Description 地域节点信息
// @Tags registry
// @Param reg_type query string true "仓库类型"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/register/regions [get]
func (s *RegistrySrv) GetRegions(ctx *gin.Context) {
	regType := ctx.Query("reg_type")
	if regType == consts.AliAcrEEVersion {
		data := []map[string]string{
			{
				"region_id":  "cn-hangzhou",
				"local_name": "华东1（杭州）",
			},
			{
				"region_id":  "cn-shanghai",
				"local_name": "华东2（上海）",
			},
			{
				"region_id":  "cn-beijing",
				"local_name": "华北2（北京）",
			},
			{
				"region_id":  "cn-zhangjiakou",
				"local_name": "华北3（张家口）",
			},
			{
				"region_id":  "cn-shenzhen",
				"local_name": "华南1（深圳）",
			},
			{
				"region_id":  "cn-heyuan",
				"local_name": "华南2（河源）",
			},
			{
				"region_id":  "cn-chengdu",
				"local_name": "西南1（成都）",
			},
			{
				"region_id":  "cn-hongkong",
				"local_name": "中国（香港）",
			},
			{
				"region_id":  "ap-northeast-1",
				"local_name": "日本（东京）",
			},
			{
				"region_id":  "ap-southeast-1",
				"local_name": "新加坡",
			},
			{
				"region_id":  "ap-southeast-2",
				"local_name": "澳大利亚（悉尼）",
			},
			{
				"region_id":  "ap-southeast-5",
				"local_name": "印度尼西亚（雅加达）",
			},
			{
				"region_id":  "eu-central-1",
				"local_name": "德国（法兰克福）",
			},
			{
				"region_id":  "eu-west-1",
				"local_name": "英国（伦敦）",
			},
			{
				"region_id":  "us-east-1",
				"local_name": "美国（弗吉尼亚）",
			},
			{
				"region_id":  "us-west-1",
				"local_name": "美国（硅谷）",
			},
			{
				"region_id":  "ap-south-1",
				"local_name": "印度（孟买）",
			},
		}
		response.JSONOK(ctx, response.WithItems(data))
		return
	}
	response.JSONOK(ctx)
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
		useType = model.UserRegistry
	}
	param := component.SearchRegistryParam{Search: search, UseType: useType}
	if regType != "" {
		param.RegType = strings.Split(strings.ReplaceAll(regType, " ", ""), ",")
	}

	registries, cnt, err := s.RegistrySrv.SearchRegistry(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	for i := range registries {
		registries[i].FitHarborVersion()
	}

	response.JSONOK(ctx, response.WithItems(registries),
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

	regs, _, err := s.RegistrySrv.SearchRegistry(ctx, component.SearchRegistryParam{Ids: []int64{id}}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(regs) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusFailedDependency, fmt.Errorf("not find registry")))
		return
	}
	reg := regs[0]
	reg.FitHarborVersion()
	response.JSONOK(ctx, response.WithItem(reg))
}

func (s *RegistrySrv) RegistryOverview(ctx *gin.Context) {

	type Body struct {
		Libraries []string `json:"libraries"`
	}
	body := new(Body)
	if err := ctx.BindJSON(body); err != nil {
		response.JSONError(ctx, fmt.Errorf("未解析到libraries"))
		return
	}
	reges, _, err := s.RegistrySrv.SearchRegistry(ctx, component.SearchRegistryParam{UseType: model.UserRegistry}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	regMap := make(map[string]model.Registry)
	for i := range reges {
		regMap[reges[i].Url] = reges[i]
	}

	type RegistryRiskInfo struct {
		RegistryUrl           string `json:"registryUrl"`
		HasContentTrustEnable bool   `json:"hasContentTrustEnable"`
		AuthEnable            bool   `json:"authEnable"`
	}
	res := make([]RegistryRiskInfo, 0)
	for i := range body.Libraries {
		url := body.Libraries[i]
		ans := RegistryRiskInfo{
			RegistryUrl:           url,
			HasContentTrustEnable: false,
			AuthEnable:            false,
		}
		if _, ok := regMap[url]; ok {
			ans.AuthEnable = true
			if strings.HasPrefix(url, "https") {
				ans.HasContentTrustEnable = true
			}
		}
		res = append(res, ans)
	}

	response.JSONOK(ctx, response.WithTotalItems(int64(len(res))), response.WithItems(res))

}

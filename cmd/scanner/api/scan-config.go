package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type ScanConfigApiSrv struct {
	ScanConfigSrv component.ScanConfigSrvInterface
}

func NewScanConfigApiSrv(scanConfigSrv component.ScanConfigSrvInterface) *ScanConfigApiSrv {
	return &ScanConfigApiSrv{ScanConfigSrv: scanConfigSrv}
}

// CreateStrategy
// @Summary CreateStrategy
// @Title 新建扫描策略
// @Author liuiqang@tensorsecurity.cn
// @Description 新建扫描策略
// @Tags scan config
// @Param body body	model.ScanStrategy true "JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/scan-config/strategy [post]
func (sc *ScanConfigApiSrv) CreateStrategy(ctx *gin.Context) {
	data := new(model.ScanStrategy)
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if err := sc.ScanConfigSrv.CreateStrategy(ctx, data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

// UpdateStrategy
// @Summary UpdateStrategy
// @Title 更新扫描策略
// @Author liuiqang@tensorsecurity.cn
// @Description 更新扫描策略
// @Tags scan config
// @Param id path int true "策略ID"
// @Param body body	model.ScanStrategy true "JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/scan-config/strategy/:id [put]
func (sc *ScanConfigApiSrv) UpdateStrategy(ctx *gin.Context) {
	data := new(model.ScanStrategy)
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	strategyID, err := strconv.ParseInt(ctx.Param("strategyID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("no strategyID for update"))
		return
	}
	if err := sc.ScanConfigSrv.UpdateStrategy(ctx, strategyID, data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)

}

// DeleteStrategy
// @Summary DeleteStrategy
// @Title 删除扫描策略
// @Author liuiqang@tensorsecurity.cn
// @Description 删除扫描策略
// @Tags scan config
// @Param id path int true "策略ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/scan-config/strategy/:id [delete]
func (sc *ScanConfigApiSrv) DeleteStrategy(ctx *gin.Context) {
	strategyID, err := strconv.ParseInt(ctx.Param("strategyID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("no strategyID for delete"))
		return
	}
	if err := sc.ScanConfigSrv.DeleteStrategy(ctx, strategyID); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

// ListStrategy
// @Summary ListStrategy
// @Title 扫描策略列表
// @Author liuiqang@tensorsecurity.cn
// @Description 扫描策略列表
// @Tags scan config
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.ScanStrategy{}}}
// @Router	/api/v1/scan-config/strategies [get]
func (sc *ScanConfigApiSrv) ListStrategy(ctx *gin.Context) {

	filter := model.GetFilter(ctx)
	filter.SortBy = "desc"
	filter.SortFiled = "updated_at"
	strategies, cnt, err := sc.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{All: consts.TrueString}, filter)

	if err != nil {
		response.JSONError(ctx, fmt.Errorf("no strategyID for create software"))
		return
	}

	response.JSONOK(ctx, response.WithItems(strategies),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// GetStrategy
// @Summary GetStrategy
// @Title 获取扫描策略详情
// @Author liuiqang@tensorsecurity.cn
// @Description 获取扫描策略详情
// @Tags scan config
// @Param id path int true "策略ID"
// @Success 200 {object} ApiWithItem{data=ApiItems{item=model.ScanStrategy{}}}
// @Router	/api/v1/scan-config/strategy/:id [get]
func (sc *ScanConfigApiSrv) GetStrategy(ctx *gin.Context) {
	strategyId, err := strconv.ParseInt(ctx.Param("strategyId"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("no strategyID "))
		return
	}

	filter := model.GetFilter(ctx)
	strategies, _, err := sc.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{StrategyID: strategyId}, filter)

	if err != nil {
		response.JSONError(ctx, fmt.Errorf("no strategyID for create software"))
		return
	}
	if len(strategies) == 0 {
		response.JSONError(ctx, fmt.Errorf("not fond stategy,strategyId:%d", strategyId))
		return
	}

	response.JSONOK(ctx, response.WithItem(strategies[0]))
}

// UpdateScanConfig
// @Summary UpdateScanConfig
// @Title 更新扫描策配置
// @Author liuiqang@tensorsecurity.cn
// @Description 更新扫描策配置
// @Tags scan config
// @Param id path int true "扫描配置ID"
// @Success 200 {object} ApiWithItem{data=ApiItems{}}
// @Router	/api/v1/scan-config/config/:id [put]
func (sc *ScanConfigApiSrv) UpdateScanConfig(ctx *gin.Context) {
	data := new(model.ScanConfig)
	if err := ctx.BindJSON(data); err != nil {
		response.JSONError(ctx, err)
		return
	}

	scanConfigID, err := strconv.ParseInt(ctx.Param("scanConfigID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("no scanConfigID for update scan config"))
		return
	}

	if err := sc.ScanConfigSrv.UpdateScanConfig(ctx, scanConfigID, data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

// SearchGlobalScanConfig
// @Summary SearchGlobalScanConfig
// @Title 获取全局扫描策配置详情
// @Author liuiqang@tensorsecurity.cn
// @Description 获取全局扫描策配置详情
// @Tags scan config
// @Param id path int true "扫描配置ID"
// @Success 200 {object} ApiWithItem{data=ApiItems{item=model.ScanConfig{}}}
// @Router	/api/v1/scan-config/config/global [get]
func (sc *ScanConfigApiSrv) SearchGlobalScanConfig(ctx *gin.Context) {
	//  暂时只会有一个config，所这里只返回一条数据,后期如果有
	configs, _, err := sc.ScanConfigSrv.SearchScanConfig(ctx, component.SearchScanConfigParam{}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(configs) == 0 {
		response.JSONError(ctx, fmt.Errorf("not fond the scan config"))
		return
	}
	response.JSONOK(ctx, response.WithItem(configs[0]))
}

// ListOpenSource
// @Summary ListOpenSource
// @Title 开源协议列表
// @Author liuiqang@tensorsecurity.cn
// @Description 开源协议列表
// @Tags scan config
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]string{}}}
// @Router	/api/v1/scan-config/strategy/open-sources [get]
func (sc *ScanConfigApiSrv) ListOpenSource(ctx *gin.Context) {
	response.JSONOK(ctx, response.WithItems(model.OpenLicense),
		response.WithTotalItems(int64(len(model.OpenLicense))))
}

// GetAllNodes
// @Summary GetAllNodes
// @Title 获取集群节点列表
// @Author liuiqang@tensorsecurity.cn
// @Description 获取集群节点列表
// @Tags scan config
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]string{}}}
// @Router	/api/v1/scan-config/strategy/node-hostnames [get]
func (sc *ScanConfigApiSrv) GetAllNodes(ctx *gin.Context) {
	nodes, err := sc.ScanConfigSrv.GetAllNodes(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(nodes),
		response.WithTotalItems(int64(len(nodes))))
}

func (sc *ScanConfigApiSrv) GetAllProject(ctx *gin.Context) {
	nodes, err := sc.ScanConfigSrv.GetAllProject(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(nodes),
		response.WithTotalItems(int64(len(nodes))))
}
func (sc *ScanConfigApiSrv) GetAllRepoName(ctx *gin.Context) {
	nodes, err := sc.ScanConfigSrv.GetAllRepoName(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(nodes),
		response.WithTotalItems(int64(len(nodes))))
}

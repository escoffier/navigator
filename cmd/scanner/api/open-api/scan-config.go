package openapi

// import (
// 	"fmt"
//
// 	"github.com/gin-gonic/gin"
//
// 	apimodel "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
// 	"gitlab.com/piccolo_su/vegeta/pkg/model"
// 	"gitlab.com/piccolo_su/vegeta/pkg/response"
// )
//
// type ScanConfigOpenAPISrv struct {
// 	ScanConfigSrv component.ScanConfigSrvInterface
// }
//
// func NewScanConfigOpenAPISrv(scanConfigSrv component.ScanConfigSrvInterface) *ScanConfigOpenAPISrv {
// 	return &ScanConfigOpenAPISrv{ScanConfigSrv: scanConfigSrv}
// }
//
// // open-api扫描策略列表
// func (sc *ScanConfigOpenAPISrv) ListStrategy2(ctx *gin.Context) {
//
// 	filter := model.GetFilterWithDefaultValue(ctx)
// 	filter.SortBy = "desc"
// 	filter.SortFiled = "updated_at"
// 	strategies, cnt, err := sc.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{All: consts.TrueString}, filter)
//
// 	if err != nil {
// 		response.JSONError(ctx, fmt.Errorf("no strategyID for create software"))
// 		return
// 	}
// 	ans := make([]apimodel.ScanStrategy, 0)
// 	for i := range strategies {
// 		ss := apimodel.ScanStrategy{
// 			ID:                    strategies[i].ID,
// 			Name:                  strategies[i].Name,
// 			Description:           strategies[i].Describe,
// 			Operator:              strategies[i].Operator,
// 			IsDefault:             strategies[i].IsDefault,
// 			SensitiveFile:         make([]string, 0),
// 			ExceptEnvs:            strategies[i].Envs,
// 			NonComplianceSoftware: strategies[i].Software,
// 			NotAllowedLicense:     strategies[i].OpenLicense,
// 		}
// 		for j := range strategies[i].SensitiveFile {
// 			ss.SensitiveFile = append(ss.SensitiveFile, strategies[i].SensitiveFile[j].Value)
// 		}
// 		ans = append(ans, ss)
// 	}
//
// 	response.JSONOK(ctx, response.WithItems(ans),
// 		response.WithTotalItems(cnt),
// 		response.WithItemsPerPage(filter.Limit),
// 		response.WithStartIndex(filter.Offset))
// }
//
// // open-api扫描策略详情
// func (sc *ScanConfigOpenAPISrv) GetStrategyByName(ctx *gin.Context) {
// 	strategyName := ctx.Param("strategyName")
//
// 	filter := model.GetFilter(ctx)
// 	strategies, _, err := sc.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{Name: strategyName}, filter)
//
// 	if err != nil {
// 		response.JSONError(ctx, fmt.Errorf("no strategyID for create software"))
// 		return
// 	}
// 	if len(strategies) == 0 {
// 		response.JSONError(ctx, fmt.Errorf("not fond stategy,strategyName:%s", strategyName))
// 		return
// 	}
// 	ss := apimodel.ScanStrategy{
// 		ID:                    strategies[0].ID,
// 		Name:                  strategies[0].Name,
// 		Description:           strategies[0].Describe,
// 		Operator:              strategies[0].Operator,
// 		IsDefault:             strategies[0].IsDefault,
// 		SensitiveFile:         make([]string, 0),
// 		ExceptEnvs:            strategies[0].Envs,
// 		NonComplianceSoftware: strategies[0].Software,
// 		NotAllowedLicense:     strategies[0].OpenLicense,
// 	}
// 	for j := range strategies[0].SensitiveFile {
// 		ss.SensitiveFile = append(ss.SensitiveFile, strategies[0].SensitiveFile[j].Value)
// 	}
//
// 	response.JSONOK(ctx, response.WithItem(ss))
// }
//
// // open-api 删除策略
// func (sc *ScanConfigOpenAPISrv) DeleteStrategyByName(ctx *gin.Context) {
// 	strategyName := ctx.Param("strategyName")
// 	strategies, _, err := sc.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{Name: strategyName}, nil)
// 	if err != nil {
// 		response.JSONError(ctx, fmt.Errorf("no strategyID for create software"))
// 		return
// 	}
// 	if len(strategies) == 0 {
// 		response.JSONError(ctx, fmt.Errorf("not fond stategy,strategyName:%s", strategyName))
// 		return
// 	}
//
// 	if err := sc.ScanConfigSrv.DeleteStrategy(ctx, strategies[0].ID); err != nil {
// 		response.JSONError(ctx, err)
// 		return
// 	}
// 	response.JSONOK(ctx)
// }
//
// // open-api 创建扫描策略
// func (sc *ScanConfigOpenAPISrv) CreateStrategy2(ctx *gin.Context) {
// 	preData := new(apimodel.ScanStrategy)
// 	if err := ctx.BindJSON(preData); err != nil {
// 		response.JSONError(ctx, err)
// 		return
// 	}
// 	data := model.ScanStrategy{
// 		Name:              preData.Name,
// 		Describe:          preData.Description,
// 		Operator:          preData.Operator,
// 		IsDefault:         false,
// 		SensitiveFile:     make([]model.SensitiveFileScan, 0),
// 		Envs:              preData.ExceptEnvs,
// 		Software:          preData.NonComplianceSoftware,
// 		OpenLicense:       preData.NotAllowedLicense,
// 		EnvsEnable:        true,
// 		SoftwareEnable:    true,
// 		OpenLicenseEnable: true,
// 		SensitiveEnable:   true,
// 		VulEnable:         true,
// 		WebshellEnable:    true,
// 		MaliciousEnable:   true,
// 	}
// 	for i := range preData.SensitiveFile {
// 		data.SensitiveFile = append(data.SensitiveFile, model.SensitiveFileScan{
// 			Value: preData.SensitiveFile[i],
// 		})
// 	}
//
// 	if err := sc.ScanConfigSrv.CreateStrategy(ctx, &data); err != nil {
// 		response.JSONError(ctx, err)
// 		return
// 	}
// 	type res struct {
// 		ID int64 `json:"id"`
// 	}
// 	re := res{ID: data.ID}
// 	response.JSONOK(ctx, response.WithItem(re))
// }
//
// // open-api 更新扫描策略
// func (sc *ScanConfigOpenAPISrv) UpdateStrategyByName(ctx *gin.Context) {
// 	preData := new(apimodel.ScanStrategy)
// 	if err := ctx.BindJSON(preData); err != nil {
// 		response.JSONError(ctx, err)
// 		return
// 	}
// 	strategyName := ctx.Param("strategyName")
//
// 	strategies, _, err := sc.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{Name: strategyName}, nil)
// 	if err != nil {
// 		response.JSONError(ctx, fmt.Errorf("no strategyID for create software"))
// 		return
// 	}
// 	if len(strategies) == 0 {
// 		response.JSONError(ctx, fmt.Errorf("not fond stategy,strategyName:%s", strategyName))
// 		return
// 	}
//
// 	data := model.ScanStrategy{
// 		Name:              preData.Name,
// 		Describe:          preData.Description,
// 		Operator:          preData.Operator,
// 		IsDefault:         false,
// 		SensitiveFile:     make([]model.SensitiveFileScan, 0),
// 		Envs:              preData.ExceptEnvs,
// 		Software:          preData.NonComplianceSoftware,
// 		OpenLicense:       preData.NotAllowedLicense,
// 		EnvsEnable:        true,
// 		SoftwareEnable:    true,
// 		OpenLicenseEnable: true,
// 		SensitiveEnable:   true,
// 		VulEnable:         true,
// 		WebshellEnable:    true,
// 		MaliciousEnable:   true,
// 	}
// 	for i := range preData.SensitiveFile {
// 		data.SensitiveFile = append(data.SensitiveFile, model.SensitiveFileScan{
// 			Value: preData.SensitiveFile[i],
// 		})
// 	}
//
// 	if err := sc.ScanConfigSrv.UpdateStrategy(ctx, strategies[0].ID, &data); err != nil {
// 		response.JSONError(ctx, err)
// 		return
// 	}
// 	response.JSONOK(ctx)
// }

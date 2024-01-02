package api

import (
	"fmt"
	"io"
	"strconv"

	"github.com/gin-gonic/gin"

	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ConfigAPISrv struct {
	sensitiveRuleService   imagesecSrv.SensitiveRuleService
	scanImageConfigService imagesecSrv.ScanImageConfigService
	scanResultService      imagescanSrv.ScanResultService
	DBManager              imagesecSrv.DBUpdateService
}

func NewConfigAPISrv(
	sensitiveRuleService imagesecSrv.SensitiveRuleService,
	scanImageConfigService imagesecSrv.ScanImageConfigService,
	scanResultService imagescanSrv.ScanResultService,
	dBManager imagesecSrv.DBUpdateService,
) *ConfigAPISrv {
	return &ConfigAPISrv{
		sensitiveRuleService:   sensitiveRuleService,
		scanImageConfigService: scanImageConfigService,
		scanResultService:      scanResultService,
		DBManager:              dBManager,
	}
}

func (s *ConfigAPISrv) CreateSensitiveRule(ctx *gin.Context) {
	data := imagesecModel.SensitiveRule{}
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	data.IsDefault = false
	if err := s.sensitiveRuleService.CreateSensitiveRule(ctx, &data); err != nil {
		response.JSONError(ctx, i18.CreateErr(err))
		return
	}

	response.JSONOK(ctx)
}

func (s *ConfigAPISrv) SearchSensitiveRule(ctx *gin.Context) {
	filter := imagesecModel.GetFilter(ctx)
	filter.SortFiled = "created_at"
	filter.SortBy = consts.SortByDesc
	ruleType := util.GetKeywordFromQuery(ctx, "ruleType")
	isDefault := util.GetKeywordFromQuery(ctx, "isDefault")
	enable := util.GetKeywordFromQuery(ctx, "enable")

	param := imagesecModel.SearchSensitiveRuleParam{
		RuleType:  ruleType,
		IsDefault: isDefault,
		Enable:    enable,
		Filter:    filter,
	}

	rule, cnt, err := s.sensitiveRuleService.SearchSensitiveRule(ctx, param)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	response.JSONOK(ctx, response.WithItems(rule),
		response.WithTotalItems(cnt))
}

func (s *ConfigAPISrv) UpdateSensitiveRule(ctx *gin.Context) {
	data := imagesecModel.SensitiveRule{}
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if err := data.Check(); err != nil {
		response.JSONError(ctx, err)
		return
	}
	id := util.GetInt64FromQuery(ctx, "id")
	if err := s.sensitiveRuleService.UpdateSensitiveRule(ctx, id, data.ToUpdater()); err != nil {
		response.JSONError(ctx, i18.UpdateErr(err))
		return
	}

	response.JSONOK(ctx)
}

func (s *ConfigAPISrv) DeleteSensitiveRule(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	if err := s.sensitiveRuleService.DeleteSensitiveRule(ctx, id); err != nil {
		response.JSONError(ctx, i18.DeleteErr(err))
		return
	}
	response.JSONOK(ctx)
}

func (s *ConfigAPISrv) GetOpenSource(ctx *gin.Context) {
	openLicense := []string{"GPL", "MIT", "Apache License", "BSD", "MPL", "FreeBSD", "ISC"}

	response.JSONOK(ctx, response.WithItems(openLicense))
}

func (s *ConfigAPISrv) GetOpenapiDoc(ctx *gin.Context) {
	type Doc struct {
		Description string `json:"description"`
		Path        string `json:"path"`
	}
	resZH := make([]Doc, 0)
	resZH = append(resZH, Doc{Description: "简介", Path: "openapi-common.html"})
	resZH = append(resZH, Doc{Description: "镜像安全 api接口", Path: "openapi-scanner.html"})
	resZH = append(resZH, Doc{Description: "合规检测 api接口", Path: "openapi-scap.html"})
	resZH = append(resZH, Doc{Description: "集群与资产 api接口", Path: "openapi-assets.html"})
	resZH = append(resZH, Doc{Description: "主动防御 api接口", Path: "openapi-defense.html"})
	resZH = append(resZH, Doc{Description: "偏移防御 api接口", Path: "openapi-drift.html"})
	resZH = append(resZH, Doc{Description: "集群安全 api接口", Path: "openapi-platform.html"})
	resZH = append(resZH, Doc{Description: "事件中心 & ATT&CK api接口", Path: "openapi-sherlock.html"})
	resZH = append(resZH, Doc{Description: "降级和恢复 api接口", Path: "openapi-degrade.html"})

	resEN := make([]Doc, 0)
	resEN = append(resEN, Doc{Description: "Info", Path: "openapi-common.html"})
	resEN = append(resEN, Doc{Description: "Image Security API", Path: "openapi-scanner.html"})
	resEN = append(resEN, Doc{Description: "Compliance API", Path: "openapi-scap.html"})
	resEN = append(resEN, Doc{Description: "Clusters Assets API", Path: "openapi-assets.html"})
	resEN = append(resEN, Doc{Description: "Active Defense API", Path: "openapi-defense.html"})
	resEN = append(resEN, Doc{Description: "Drift Defense API", Path: "openapi-drift.html"})
	resEN = append(resEN, Doc{Description: "Cluster Security API", Path: "openapi-platform.html"})
	resEN = append(resEN, Doc{Description: "Event Center & ATT&CK API", Path: "openapi-sherlock.html"})
	resEN = append(resEN, Doc{Description: "Downgrade Recovery API", Path: "openapi-degrade.html"})

	res := resZH
	if GetLanguage(ctx) == consts.LangEN {
		res = resEN
	}

	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(int64(len(res))))
}

func (s *ConfigAPISrv) GetConstView(ctx *gin.Context) {
	constType := util.GetKeywordFromQuery(ctx, "constType")
	view := s.scanImageConfigService.GetConstView(ctx, constType)
	lang := util.GetLanguage(ctx)
	if lang == imagesecModel.LangEn {
		response.JSONOK(ctx, response.WithItems(view.EN))
		return
	}
	response.JSONOK(ctx, response.WithItems(view.ZH))
}

func (s *ConfigAPISrv) GetScanImageConfig(ctx *gin.Context) {
	configType := util.GetKeywordFromQuery(ctx, "configType")
	if configType == "" {
		response.JSONError(ctx, fmt.Errorf("not get configType"))
		return
	}

	data, err := s.scanImageConfigService.GetScanImageConfig(ctx, configType)
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}
	response.JSONOK(ctx, response.WithItem(data.ImageScanConfig))
}

func (s *ConfigAPISrv) UpdateScanImageConfig(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	configType := util.GetKeywordFromQuery(ctx, "configType")
	imageConfig := imagesecModel.ImageScanConfig{}

	err := ctx.BindJSON(&imageConfig)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	m := &imagesecModel.ScanImageConfig{ImageScanConfig: &imageConfig, ConfigType: configType}

	if err := s.scanImageConfigService.UpdateScanImageConfig(ctx, id, m); err != nil {
		response.JSONError(ctx, i18.UpdateErr(err))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(id))}))
}

func (s *ConfigAPISrv) GetLicense(ctx *gin.Context) {
	uniqueID := util.GetUint64FromQuery(ctx, "uniqueID")

	param := imagesecModel.ScanResultSearchParam{
		UniqueIds: []uint64{uniqueID},
		Fields:    []string{"id", "unique_id", "name"},
	}

	li, err := s.scanResultService.SearchLicense(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(li) == 0 {
		response.JSONError(ctx, scani18.NotGetLicenseInfo())
		return
	}
	response.JSONOK(ctx, response.WithItem(li[0]))
}

func (s *ConfigAPISrv) SearchLicense(ctx *gin.Context) {

	param := imagesecModel.ScanResultSearchParam{
		Fields: []string{"id", "unique_id", "name"},
	}

	li, err := s.scanResultService.SearchLicense(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(li))
}

func (s *ConfigAPISrv) UpdateVulnDB(ctx *gin.Context) {
	updater := ctx.Query("updater")
	checkVersion := util.GetBoolStringFromQuery(ctx, "checkVersion")

	file, err := ctx.FormFile("file")
	if err != nil {
		response.JSONError(ctx, i18.CreateI18BadReqErr("未获取到db文件", "not get db file"))
		return
	}

	// 打开上传的文件
	src, err := file.Open()
	if err != nil {
		response.JSONError(ctx, i18.CreateI18BadReqErr("打开文件失败", "can not open db file"))
		return
	}
	defer func() { _ = src.Close() }()

	// 将文件内容读取为字节切片 ([]byte)
	bts, err := io.ReadAll(src)
	if err != nil {
		response.JSONError(ctx, i18.CreateI18BadReqErr("读取文件失败", "can not read db file"))
		return
	}
	param := imagesecModel.UpdateDbParam{
		Updater:      updater,
		DbType:       consts.TrivyName,
		Data:         bts,
		CheckVersion: checkVersion == consts.TrueString,
	}
	err = s.DBManager.UpdateVulnDb(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx)
}

func (s *ConfigAPISrv) UpdateAviraDB(ctx *gin.Context) {

	// updater := ctx.Query("updater")
	// checkVersion := util.GetBoolStringFromQuery(ctx, "checkVersion")
	//
	// file, err := ctx.FormFile("file")
	// if err != nil {
	// 	response.JSONError(ctx, i18.CreateI18BadReqErr("未获取到db文件", "not get db file"))
	// 	return
	// }
	//
	// // 打开上传的文件
	// src, err := file.Open()
	// if err != nil {
	// 	response.JSONError(ctx, i18.CreateI18BadReqErr("打开文件失败", "can not open db file"))
	// 	return
	// }
	// defer func() { _ = src.Close() }()
	//
	// // 将文件内容读取为字节切片 ([]byte)
	// bts, err := io.ReadAll(src)
	// if err != nil {
	// 	response.JSONError(ctx, i18.CreateI18BadReqErr("读取文件失败", "can not read db file"))
	// 	return
	// }
	// param := imagesecModel.UpdateDbParam{
	// 	Updater:      updater,
	// 	DbType:       consts.AviraName,
	// 	Data:         bts,
	// 	CheckVersion: checkVersion == consts.TrueString,
	// }
	// err = s.DBManager.UpdateAviraDB(ctx, param)
	// if err != nil {
	// 	response.JSONError(ctx, err)
	// 	return
	// }

	response.JSONOK(ctx)
}

func (s *ConfigAPISrv) SearchDB(ctx *gin.Context) {
	dbType := util.GetKeywordFromQuery(ctx, "dbType")
	filter := imagesecModel.GetFilter(ctx).SetSortFiledByID().SetSortDesc()
	lis, cnt, err := s.DBManager.SearchScanDb(ctx, imagesecModel.SearchScanDbParam{
		DBType: dbType,
		Filter: filter,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	// 兼容前端
	type HistoryResp struct {
		CompressVersion string `json:"version"`
		UpdateTime      int64  `json:"updateTime"`
		DBType          string `json:"dbType"`
		Updater         string `json:"updater"`
	}
	ans := make([]HistoryResp, 0)
	for i := range lis {
		ans = append(ans, HistoryResp{
			CompressVersion: lis[i].DBVersion,
			UpdateTime:      lis[i].UpdatedAt,
			DBType:          lis[i].DBType,
			Updater:         lis[i].Updater,
		})
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ConfigAPISrv) LatestVersion(ctx *gin.Context) {
	filter := imagesecModel.GetFilter(ctx)
	filter = filter.SetSortDesc().SetSortFiled("id").SetLimit(1)
	// 暂时只查漏洞库，后期要改成查全部
	lis, cnt, err := s.DBManager.SearchScanDb(ctx, imagesecModel.SearchScanDbParam{
		DBType: consts.TrivyName,
		Filter: filter,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	// 兼容前端
	type HistoryResp struct {
		CompressVersion string `json:"version"`
		UpdateTime      int64  `json:"updateTime"`
		DBType          string `json:"dbType"`
		Updater         string `json:"updater"`
	}
	ans := make([]HistoryResp, 0)
	for i := range lis {
		ans = append(ans, HistoryResp{
			CompressVersion: lis[i].DBVersion,
			UpdateTime:      lis[i].UpdatedAt,
			DBType:          lis[i].DBType,
			Updater:         lis[i].Updater,
		})
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

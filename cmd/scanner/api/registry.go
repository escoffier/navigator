package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	imagesec2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	registryService "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/service"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RegistrySrv struct {
	RegistrySrv   registryService.RegistryService
	ScannerInsSrv imagesec2.ScanInstanceService
	RejectSrv     imagesec2.TrustedImageService
}

func NewRegistrySrv(
	registrySrv registryService.RegistryService,
	rejectSrv imagesec2.TrustedImageService,
	scannerInstance imagesec2.ScanInstanceService) *RegistrySrv {
	return &RegistrySrv{RegistrySrv: registrySrv, RejectSrv: rejectSrv, ScannerInsSrv: scannerInstance}
}

func (s *RegistrySrv) UpdateRegistry(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")

	reg := new(imagesec.Registry)
	if err := ctx.BindJSON(reg); err != nil {
		response.JSONError(ctx, err)
		return
	}

	err := s.RegistrySrv.UpdateRegistry(ctx, id, *reg)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: reg.Name,
		ID:   strconv.FormatInt(reg.ID, 10),
		Link: "api/v2/containerSec/scanner/syncImage/registry",
	}))
}

func (s *RegistrySrv) CreateRegistry(ctx *gin.Context) {
	// 做一下兼容
	reg := &imagesec.Registry{}
	if err := ctx.BindJSON(reg); err != nil {
		response.JSONError(ctx, err)
		return
	}
	err := s.RegistrySrv.CreateRegistry(ctx, reg)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: reg.Name,
		ID:   strconv.FormatInt(reg.ID, 10),
		Link: "api/v2/containerSec/scanner/syncImage/registry",
	}))
}

func (s *RegistrySrv) DeleteRegistry(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	if err := s.RegistrySrv.DeleteRegistry(ctx, id); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: fmt.Sprintf("%d", id),
		ID:   strconv.FormatInt(id, 10),
		Link: "api/v2/containerSec/scanner/syncImage/registry",
	}))
}

func (s *RegistrySrv) GetRegistryType(ctx *gin.Context) {

	ans, err := s.RegistrySrv.GetRegistryType(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(ans))
}

func (s *RegistrySrv) GetRegions(ctx *gin.Context) {
	regType := ctx.Query("regType")
	if regType == imagesec.AliAcrEEVersion {
		data := []map[string]string{
			{
				"regionID":  "cn-hangzhou",
				"localName": "华东1（杭州）",
			},
			{
				"regionID":  "cn-shanghai",
				"localName": "华东2（上海）",
			},
			{
				"regionID":  "cn-beijing",
				"localName": "华北2（北京）",
			},
			{
				"regionID":  "cn-zhangjiakou",
				"localName": "华北3（张家口）",
			},
			{
				"regionID":  "cn-shenzhen",
				"localName": "华南1（深圳）",
			},
			{
				"regionID":  "cn-heyuan",
				"localName": "华南2（河源）",
			},
			{
				"regionID":  "cn-chengdu",
				"localName": "西南1（成都）",
			},
			{
				"regionID":  "cn-hongkong",
				"localName": "中国（香港）",
			},
			{
				"regionID":  "ap-northeast-1",
				"localName": "日本（东京）",
			},
			{
				"regionID":  "ap-southeast-1",
				"localName": "新加坡",
			},
			{
				"regionID":  "ap-southeast-2",
				"localName": "澳大利亚（悉尼）",
			},
			{
				"regionID":  "ap-southeast-5",
				"localName": "印度尼西亚（雅加达）",
			},
			{
				"regionId":  "eu-central-1",
				"localName": "德国（法兰克福）",
			},
			{
				"regionID":  "eu-west-1",
				"localName": "英国（伦敦）",
			},
			{
				"regionID":  "us-east-1",
				"localName": "美国（弗吉尼亚）",
			},
			{
				"regionID":  "us-west-1",
				"localName": "美国（硅谷）",
			},
			{
				"regionID":  "ap-south-1",
				"localName": "印度（孟买）",
			},
		}
		response.JSONOK(ctx, response.WithItems(data))
		return
	}
	response.JSONOK(ctx)
}

func (s *RegistrySrv) SearchRegistry(ctx *gin.Context) {
	name := util.GetKeywordFromQuery(ctx, "name")
	url := util.GetKeywordFromQuery(ctx, "url")
	regType := util.GetStringSliceFromQuery(ctx, "regType")
	status := util.GetStringSliceFromQuery(ctx, "status")
	startSyncAt := util.GetInt64FromQuery(ctx, "startTime")
	endSyncAt := util.GetInt64FromQuery(ctx, "endTime")

	filter := imagesec.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit).SetSortDesc().SetSortFiled("id")

	param := imagesec.SearchRegistryParam{
		RegType:     regType,
		NameKeyword: name,
		UrlKeyword:  url,
		Status:      status,
		StartSyncAt: startSyncAt,
		EndSyncAt:   endSyncAt,
		Deleted:     consts.FalseString,
		Filter:      filter,
	}

	registries, cnt, err := s.RegistrySrv.SearchRegistry(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	for i := range registries {
		registries[i].FitHarborVersion()
		registries[i].HidePassword()
	}

	instances, err := s.ScannerInsSrv.SearchScannerInfo(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	instanceMap := make(map[string]imagesec.ScannerInstanceInfo)
	for i := range instances {
		instanceMap[instances[i].ScannerInstance] = instances[i]
	}
	for i := range registries {
		abn := false
		ins, ok := instanceMap[registries[i].ScannerInstance]
		if !ok {
			abn = true
		}

		if time.Now().Unix()-ins.HeartBeatAt > 5*60 && util.ThanVersion(ins.ScannerVersion, consts.ScannerVersion211) {
			abn = true

		}
		if abn {
			if GetLanguage(ctx) == consts.LangEN {
				registries[i].ScannerInstance = ins.ScannerInstance + "(abnormal)"
			} else {
				registries[i].ScannerInstance = ins.ScannerInstance + "(异常)"
			}
		}
	}

	response.JSONOK(ctx, response.WithItems(registries),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *RegistrySrv) GetRegistry(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	needPasswd := util.GetBoolStringFromQuery(ctx, "needPasswd")
	regs, _, err := s.RegistrySrv.SearchRegistry(ctx, imagesec.SearchRegistryParam{RegIds: []int64{id}})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(regs) == 0 {
		response.JSONError(ctx, scani18.SearchReg(fmt.Errorf("not find registry")))
		return
	}
	reg := regs[0]
	reg.FitHarborVersion()
	if needPasswd != consts.TrueString {
		reg.HidePassword()
	}
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
	reges, _, err := s.RegistrySrv.SearchRegistry(ctx, imagesec.SearchRegistryParam{})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	regMap := make(map[string]imagesec.Registry)
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

func (s *RegistrySrv) CreateSyncTask(ctx *gin.Context) {
	param := SyncImageParam{}
	if err := ctx.BindJSON(&param); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if param.RegistryID <= 0 {
		response.JSONError(ctx, scani18.NotGetRegID())
		return
	}

	if err := s.RegistrySrv.CreateSyncTask(ctx, imagesec.CreateSyncTaskParam{
		RegID:    param.RegistryID,
		SyncType: imagesec.ManualSync,
	}); err != nil {
		logging.GetLogger().Err(err).Msg("CreateSyncTask")
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx,
		response.WithItem(ResponseMsg{RegistryID: param.RegistryID, Msg: fmt.Sprintf("开启同步任务:registryID:%d", param.RegistryID)}),
		response.WithTarget(&response.TargetRef{
			Name: fmt.Sprintf("registry %d", param.RegistryID),
			ID:   strconv.Itoa(int(param.RegistryID)),
			Link: "api/v2/containerSec/scanner/syncImage/startSync",
		}),
	)
}

func (s *RegistrySrv) StartSyncByRegName(ctx *gin.Context) {
	param := SyncImageParam{}
	if err := ctx.BindJSON(&param); err != nil {
		response.JSONError(ctx, err)
		return
	}

	if param.RegistryName == "" {
		response.JSONError(ctx, fmt.Errorf("not get registryName:%s", param.RegistryName))
		return
	}

	regs, _, err := s.RegistrySrv.SearchRegistry(ctx, imagesec.SearchRegistryParam{Name: param.RegistryName})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(regs) == 0 {
		response.JSONError(ctx, fmt.Errorf("not find registry:%s", param.RegistryName))
		return
	}

	err = s.RegistrySrv.CreateSyncTask(ctx, imagesec.CreateSyncTaskParam{
		RegID:    regs[0].ID,
		SyncType: imagesec.ManualSync,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("StartSyncAllImage")
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}
	response.JSONOK(ctx,
		response.WithItem(ResponseMsg{RegistryID: regs[0].ID, RegistryName: param.RegistryName, Msg: fmt.Sprintf("开启同步任务:registryName:%s", param.RegistryName)}))
}

func (s *RegistrySrv) GetSyncProgress(ctx *gin.Context) {

}

func (s *RegistrySrv) GetSyncStatus(ctx *gin.Context) {
	status, err := s.RegistrySrv.GetSyncStatus(ctx)

	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(status))
}

type SyncImageParam struct {
	RegistryID   int64  `json:"registryID"`
	RegistryName string `json:"registryName"`
}

type ResponseMsg struct {
	Msg          string `json:"msg"`
	RegistryID   int64  `json:"registryID"`
	RegistryName string `json:"registryName"`
}

type ResponseGetSyncStatus struct {
	Status     bool  `json:"status"`
	RegistryID int64 `json:"registryID"`
}

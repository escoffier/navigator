package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm/clause"

	apimodel "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Scanner struct {
	Srv           component.ScannerSrv
	VulnSrv       component.VulnServiceInterface
	RegistrySrv   component.RegistrySrvInterface
	ScanConfigSrv component.ScanConfigSrvInterface
	ImageSrv      component.ImageSrvInterface
}

// TickOnlineScan
// @Summary TickOnlineScan
// @Title TickOnlineScan
// @Author guolingkai@tensorsecurity.cn
// @Description k8s&在线监控生成接口
// @Tags image reject
// @Param body body	[]model.RejectOnlineMoniterImage{NotifyContext=model.NotifyContext{CustomKV=[]model.KVHashs{KVHash=model.KVHash{}}}} true "JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=OnlyFlagRes{}}}
// @Router	/api/v1/imagereject/online_moniter [post]
func (s *Scanner) TickOnlineScan(ctx *gin.Context) {
	start := time.Now().UnixMicro()
	containerInfo := make([]model.RejectOnlineMonitorImage, 0)
	if err := ctx.BindJSON(&containerInfo); err != nil {
		logging.Get().WithContext(ctx).Errorf(err, "BindJSON error")
		return
	}
	if len(containerInfo) == 0 {
		logging.Get().WithContext(ctx).Infof("收到TickOnlineScan,空数据")
		return
	}

	logging.Get().Debug().Msgf("收到TickOnlineScan,from_type:%s,image:%+v", containerInfo[0].FromType, containerInfo)
	flag := s.Srv.TickOnlineScan(ctx, containerInfo)
	type tmpRes struct {
		Flag bool `json:"flag"`
	}
	res := tmpRes{}
	res.Flag = flag
	logging.Get().Debug().Msgf("查询完成TickOnlineScan,from_type:%s,image:%s,safe:%t cast：%d", containerInfo[0].FromType, containerInfo[0].Image, res.Flag, time.Now().UnixMicro()-start)
	response.JSONOK(ctx, response.WithItem(res))
}

// GetSimpleImageDetail
// @Summary reportsBySimpleImageDetails
// @Title reportsBySimpleImageDetails
// @Author guolingkai@tensorsecurity.cn
// @Description 获取简略的镜像扫描详情（目前只有风险探索页面在使用，没有前端访问）
// @Tags Internal API
// @Param tag query  string true "image tag"
// @Param digest query  string true "image digest"
// @Param library query  string true "image from library"
// @Param full_repo_name query  string true "image full_repo_name"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.SimpleImageDetail{sensitive_info=[]model.Sensitive{},vuln_info=[]model.VulnerabilityInfo{}}}}
// @Router	/api/v1/scan/reportsBySimpleImageDetails [get]
func (s *Scanner) GetSimpleImageDetail(ctx *gin.Context) {
	tag := ctx.Query("tag")
	digest := ctx.Query("digest")
	library := ctx.Query("library")
	fullRepoName := ctx.Query("full_repo_name")
	res := s.Srv.GetSimpleImageDetail(ctx, tag, digest, library, fullRepoName)
	response.JSONOK(ctx, response.WithItem(res))
}

// ListImageInfoFromVuln
// query/:name
// @Summary query/:name
// @Title query/:name
// @Author guolingkai@tensorsecurity.cn
// @Description 用于console通过vuln_nmae获取关联镜像信息
// @Tags Internal API
// @Param name query string true "vuln name like CVE-2020-XXXX"
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.VulnImageList{}}}
// @Router /api/v1/vulns/query [get]
func (s *Scanner) ListImageInfoFromVuln(ctx *gin.Context) {
	vulnName := ctx.Query("vulnName")
	pkgName := ctx.Query("pkgName")
	pkgVersion := ctx.Query("pkgVersion")

	if vulnName == "" || pkgName == "" || pkgVersion == "" {
		response.JSONError(ctx, fmt.Errorf("vulnName,pkgName,pkgVersion must not empty"))
		return
	}
	uniqueVuln := util.GenerateUUID64(fmt.Sprintf(consts.UniqueVulnFamat, vulnName, pkgName, pkgVersion))

	res, err := s.Srv.GetImagesFromVuln(ctx, uniqueVuln)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

// ScannedByVulnDetails
// detail/:name
// @Summary detail/:name
// @Title detail/:name
// @Author guolingkai@tensorsecurity.cn
// @Description 获取漏洞详细信息
// @Tags Vuln
// @Param name query string true "vuln name"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.VulnDetail{}}}
// @Router /api/v1/vulns/detail [get]
func (s *Scanner) ScannedByVulnDetails(ctx *gin.Context) {

	vulnName := ctx.Query("vulnName")
	pkgName := ctx.Query("pkgName")
	pkgVersion := ctx.Query("pkgVersion")

	if vulnName == "" || pkgName == "" || pkgVersion == "" {
		response.JSONError(ctx, fmt.Errorf("vulnName,pkgName,pkgVersion must not empty"))
		return
	}
	uniqueVuln := util.GenerateUUID64(fmt.Sprintf(consts.UniqueVulnFamat, vulnName, pkgName, pkgVersion))

	vulns, _, err := s.VulnSrv.SearchVulns(ctx, component.SearchVulnParam{UniqueVulns: []uint64{uniqueVuln}}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(vulns) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond vuln")))
		return
	}
	// 数据转换，兼容前端
	vuln := vulns[0]
	res := model.VulnDetail{
		VulninfoApi: model.VulnDetailInfo{
			ID:          vuln.ID,
			UniqueVuln:  vuln.UniqueVuln,
			Name:        vuln.Name,
			Severity:    vuln.Severity,
			Pkgname:     vuln.PkgName,
			Pkgversion:  vuln.PkgVersion,
			Links:       vuln.Link,
			Fixedby:     vuln.FixedBy,
			Description: vuln.Description,
		}}
	if vuln.Metadata != nil {
		res.VulninfoApi.Cvss = vuln.Metadata.CVSS
		res.VulninfoApi.Cnvd = vuln.Metadata.CNVDs
		res.VulninfoApi.CNNVDs = vuln.Metadata.CNNVDs
	}

	response.JSONOK(ctx, response.WithItem(res))
}

// SearchVulns
// all
// @Summary all
// @Title all
// @Author guolingkai@tensorsecurity.cn
// @Description 获取在线镜像漏洞列表
// @Tags Vuln
// @Param search query string false "for vuln like "
// @Param offset query int true "int"
// @Param limit query int true "int"
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.Vuln{}}}
// @Router	/api/v1/vulns/all [get]
func (s *Scanner) SearchVulns(ctx *gin.Context) {
	search := ctx.Query("search")
	if len(search) > 64 {
		response.JSONError(ctx, errors.New("the maximum value is exceeded"))
		return
	}
	filter := model.GetFilter(ctx)
	if filter.SortFiled == "" {
		filter.SortFiled = "severity_int"
	}
	if filter.SortBy == "" {
		filter.SortBy = consts.SortByDesc
	}
	// 默认查在线的
	onlineIds, err := s.Srv.GetOnlineImageId(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(onlineIds) == 0 {
		response.JSONOK(ctx, response.WithItems([]model.Vuln{}))
		return
	}

	vulns, cnt, err := s.VulnSrv.SearchVulns(ctx, component.SearchVulnParam{ImageIds: onlineIds, VulnKeyword: search}, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	res := make([]VulnResponse, len(vulns))
	for i := range vulns {
		res[i] = convertVuln(vulns[i])
	}
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// ListScannedByVulnOverview
// statistic
// @Summary statistic
// @Title statistic
// @Author guolingkai@tensorsecurity.cn
// @Description 获取漏洞视角概览信息
// @Tags Vuln
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.VulnOverview{top5=[]model.ImageRiskScore{}}}}
// @Router	/api/v1/vulns/statistic [get]
func (s *Scanner) ListScannedByVulnOverview(ctx *gin.Context) {
	res, err := s.Srv.GetOnlineVulnOverView(ctx)
	if err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}
	response.JSONOK(ctx, response.WithItem(res), response.WithExportFileStatus(0))
}

// GetVulnTopNImage
// @Summary 获取漏洞评分Top5的镜像
// @Title statistic
// @Author guolingkai@tensorsecurity.cn
// @Description 获取漏洞评分Top5的镜像
// @Tags Vuln
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.VulnOverview{top5=[]model.ImageRiskScore{}}}}
// @Router	/api/v1/vulns/statistic [get]
func (s *Scanner) GetVulnTopNImage(ctx *gin.Context) {

	topN, err := strconv.ParseInt(ctx.Query("topn"), 10, 64)
	if err != nil {
		topN = consts.DefaultVulnTopNImage
	}

	res, err := s.Srv.GetOnlineVulnTopN(ctx, topN)
	if err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(int64(len(res))))
}

func (s *Scanner) GetImageHistogram(ctx *gin.Context) {

	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond imageID")))
		return
	}
	res, err := s.Srv.GetImageSeverityCount(ctx, imageID)
	if err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}
	response.JSONOK(ctx, response.WithItem(res), response.WithExportFileStatus(0))
}

// CreateScanImageTask
// @Summary CreateScanImageTask
// @Title CreateScanImageTask
// @Author guolingkai@tensorsecurity.cn
// @Description 扫描全部列表中的镜像
// @Tags scan image
// @Success 200 {object} ApiWithItem{data{}}
// @Router	/api/v1/tasks/task [post]
func (s *Scanner) CreateScanImageTask(ctx *gin.Context) {
	body := model.ImageListParam{}

	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}

	taskInfo := task.UpdateTaskInfo{
		Scope:        consts.FullScan,
		TriggerType:  consts.ManualTrigger,
		StrategyID:   body.ImageScanTaskInfo.StrategyID,
		StrategyName: body.ImageScanTaskInfo.StrategyName,
		Operator:     body.ImageScanTaskInfo.Operator,
	}

	go func() {
		if err := s.ImageSrv.CreateScanImageTask(ctx, body, taskInfo); err != nil {
			logging.Get().Err(err).Msg("scan all error")
		}
	}()

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: "CreateScanImageTask",
		Link: "api/v2/containerSec/scanner/tasks/CreateScanImageTask",
	}))
}

// StartScanOne
// @Summary ScanOne
// @Title ScanOne
// @Author guolingkai@tensorsecurity.cn
// @Description 扫描列表中某一个镜像，参数为单个id
// @Tags scan image
// @Param body body OnlyIDRes true "Json数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=OnlyStatusRes{}}}
// @Router	/api/v1/scan/scanone [post]
func (s *Scanner) StartScanOne(ctx *gin.Context) {
	type resp struct {
		Status string `json:"status"`
	}
	type tmpRecv struct {
		ImgID      int64  `json:"id"`
		Operator   string `json:"operator"`
		StrategyID int64  `json:"strategy_id"`
	}
	tmp := tmpRecv{}
	// json := make(map[string]interface{})
	if err := ctx.BindJSON(&tmp); err != nil {
		response.JSONError(ctx, err)
		return
	}
	err := s.Srv.TickScanOne(ctx, tmp.ImgID, task.UpdateTaskInfo{
		Scope:       consts.SingleScan,
		TriggerType: consts.ManualTrigger,
		Operator:    tmp.Operator,
		StrategyID:  tmp.StrategyID,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(resp{Status: "OK"}))
}

func (s *Scanner) SearchImageWithScan(ctx *gin.Context) {
	body := model.ImageListParam{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	filter := model.GetFilterWithDefaultValue(ctx)

	images, cnt, err := s.ImageSrv.ListImageWithScanInfo(ctx, body, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(images),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *Scanner) GetRegistryProject(ctx *gin.Context) {
	regID, _ := strconv.ParseInt(ctx.Query("regID"), 10, 64)
	projectKeyword := ctx.Query("projectKeyword")

	repos, err := s.ImageSrv.GetRegistryProject(ctx, component.GetRegistryProjectParam{
		RegID:          regID,
		ProjectKeyword: projectKeyword,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(repos),
		response.WithTotalItems(int64(len(repos))))
}

// ScanOneForCICDRequest
// @Summary 获取CICD扫描结果
// @Title 获取CICD扫描结果
// @Author guolingkai@tensorsecurity.cn
// @Description CICD的第二个API，获取CICD扫描结果
// @Tags image reject
// @Param body body model.ScanOneCICDResultRequest true "JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.ScanOneForCICDResponse{}}}
// @Router	/api/v1/imagereject/result/cicd [post]
func (s *Scanner) ScanOneForCICDRequest(ctx *gin.Context) {
	tmp := new(model.ScanOneCICDResultRequest)

	if err := ctx.BindJSON(tmp); err != nil {
		response.JSONError(ctx, err)
		return
	}
	resp, err := s.Srv.ScanOneForCICDResult(ctx, tmp)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if resp != nil {
		// 整理数据
		resp.Vuln = make([][]string, 0)
		resp.RejectMsg = make([][]string, 0)
		resp.Sensitive = make([][]string, 0)
		resp.Virus = make([][]string, 0)
		resp.Webshell = make([][]string, 0)

		if len(resp.Msg) > 0 {
			resp.RejectMsg = append(resp.RejectMsg, []string{"扫描命中策略"})
			for i := range resp.Msg {
				resp.RejectMsg = append(resp.RejectMsg, []string{resp.Msg[i].KVHash.ZH.Value})
			}
		}

		// 拼装镜像扫描数据数据
		// 先看漏洞
		if resp.ImageDetail != nil && len(resp.ImageDetail.ImageScanVuln.Vulns) > 0 {
			resp.Vuln = append(resp.Vuln, []string{"漏洞编号", "严重程度", "软件包", "软件版本"})
			for _, vu := range resp.ImageDetail.ImageScanVuln.Vulns {
				resp.Vuln = append(resp.Vuln, []string{vu.Name, vu.Severity, vu.PkgName, vu.PkgVersion})
			}
		}
		// 再看敏感文件
		if resp.ImageDetail != nil && len(resp.ImageDetail.ImageScanVuln.SensitiveFiles) > 0 {
			resp.Sensitive = append(resp.Sensitive, []string{"敏感文件名", "文件路径", "文件类型"})
			for _, vu := range resp.ImageDetail.ImageScanVuln.SensitiveFiles {
				split := strings.Split(vu.Name, "/")
				if len(split) < 1 {
					continue
				}
				resp.Sensitive = append(resp.Sensitive, []string{split[len(split)-1], vu.Name, ""})
			}
		}
		// 再查恶意文件
		if resp.ImageDetail != nil && len(resp.ImageDetail.ImageScanVirus) > 0 {
			resp.Virus = append(resp.Virus, []string{"恶义病毒名", "文件名", "文件路径"})
			for _, vu := range resp.ImageDetail.ImageScanVirus {
				resp.Virus = append(resp.Virus, []string{vu.Virusname, vu.Filename, vu.Filepath})
			}
		}
		// 再看websell
		if resp.ImageDetail != nil && len(resp.ImageDetail.ImageScanWebshell) > 0 {
			resp.Webshell = append(resp.Webshell, []string{"文件名", "文件路径", "评分", "代码详情"})
			for _, vu := range resp.ImageDetail.ImageScanWebshell {
				resp.Webshell = append(resp.Webshell, []string{vu.Filename, vu.Filepath, strconv.Itoa(int(vu.Score)), strings.Join(vu.Codes, ",")})
			}
		}
		// 再看环境变量
		if resp.ImageDetail != nil && resp.ImageDetail.ImageScanEnv != nil {
			resp.Envs = append(resp.Envs, []string{"环境变量名", "环境变量值"})
			for _, vu := range resp.ImageDetail.ImageScanEnv {
				resp.Envs = append(resp.Envs, []string{vu.EnvName, vu.EnvValue})
			}
		}
	} else {
		resp = &model.ScanOneForCICDResponse{}
		resp.IsScan = false
	}
	response.JSONOK(ctx, response.WithItem(*resp))
}

// ScanOneForDetectImage
// @Summary 用于触发CICD扫描
// @Title 用于触发CICD扫描
// @Author guolingkai@tensorsecurity.cn
// @Description CICD的第一个API，用于触发CICD扫描
// @Tags image reject
// @Param body body model.ScanOneForCICDRequest true "JSON数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.ScanOneStatusResponse{}}}
// @Router	/api/v1/imagereject/scanone/cicd [post]
func (s *Scanner) ScanOneForDetectImage(ctx *gin.Context) {
	tmp := new(model.ScanOneForCICDRequest)

	if err := ctx.BindJSON(tmp); err != nil {
		response.JSONError(ctx, err)
		return
	}
	logging.Get().WithContext(ctx).Infof("CICD 收到的请求,image:%s,Insecure:%t", tmp.Image, tmp.Insecure)

	hasHTTP := strings.Contains(tmp.Image, "http://")
	hasHTTPS := strings.Contains(tmp.Image, "https://")
	if !hasHTTPS && !hasHTTP {
		if !tmp.Insecure {
			tmp.Image = "https://" + tmp.Image
		} else {
			tmp.Image = "http://" + tmp.Image
		}
	}
	resp, err := s.Srv.ScanOneForCICD(ctx, tmp)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*resp))
}

// ListScannedByImageOverview
// @Summary reportsByImageOverview
// @Title 获取单个镜像的扫描状态
// @Author guolingkai@tensorsecurity.cn
// @Description 获取单个镜像的扫描状态
// @Tags scan image
// @Param fromUrl query string false "registry url"
// @Success 200 {object} ApiWithItem{data=ApiWithItem{item=model.OverView{online=model.SafeOver{}}}}
// @Router	/api/v1/scan/reportsByImageOverview [get]
func (s *Scanner) ListScannedByImageOverview(ctx *gin.Context) {
	fromType, err := strconv.ParseInt(ctx.Query("from_type"), 10, 64)
	if err != nil {
		fromType = model.UserRegistry
	}

	view, err := s.Srv.GetImageOverView(ctx, fromType)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*view))
}

// ScannedByImageDetails
// @Summary reportsByImageDetails
// @Title reportsByImageDetails
// @Author guolingkai@tensorsecurity.cn
// @Description 获取单个镜像的扫描状态
// @Tags scan image
// @Param id query int ture "image id"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.ImageList{questions=[]model.QuestionInfo{},image_scan_vuln=model.ImageScanSummaryResult{},image_scan_virus=[]model.VirusFileInfo}}}
// @Router	/api/v1/scan/reportsByImageDetails [get]
func (s *Scanner) ScannedByImageDetails(ctx *gin.Context) {
	imgID, err := strconv.ParseInt(ctx.Query("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, errors.New("no image id"))
		return
	}
	img, err := s.Srv.GetImageDetail(ctx, imgID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 精简数据
	img.Registry = nil
	img.ConfigJSON = nil
	img.ConfigFile = nil
	img.ManifestV2 = nil
	img.ManifestV2JSON = nil
	img.ManifestV1 = nil
	img.ManifestV1JSON = nil
	img.ImageScanVuln.Vulns = nil

	// 对web界面上的修复建议，不要表头文案
	if len(img.VulnFixSuggestion) > 0 {
		img.VulnFixSuggestion = img.VulnFixSuggestion[1:]
	}
	if len(img.SentiveFixSuggestion) > 0 {
		img.SentiveFixSuggestion = img.SentiveFixSuggestion[1:]
	}

	response.JSONOK(ctx, response.WithItem(*img))
}

// SearchImages
// @Summary SearchImages
// @Title SearchImages
// @Author liuqiang@tensorsecurity.cn
// @Description 只查询镜像列表，不查询有镜像相关的数据
// @Tags scan image
// @Param search query string false "for image like "
// @Param offset query int true "int"
// @Param limit query int true "int"
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.ImageResponse{}}}
// @Router	/api/v1/images/sampleList [get]
func (s *Scanner) SearchImages(ctx *gin.Context) {
	search := ctx.Query("search")
	if len(search) > 64 {
		response.JSONError(ctx, errors.New("the maximum value is exceeded"))
		return
	}

	fromType, err := strconv.ParseInt(ctx.Query("from_type"), 10, 64)
	if err != nil || fromType == 0 {
		fromType = model.UserRegistry
	}

	filter := model.GetFilter(ctx)
	param := component.SearchImageParam{
		Search:   search,
		FromType: fromType,
	}
	uuids := ctx.Query("uuids")
	if uuids != "" {
		uuid := make([]uint32, 0)
		split := strings.Split(uuids, ",")
		for i := range split {
			if parseInt, err := strconv.ParseInt(split[i], 10, 64); err != nil {
				logging.Get().Err(err).Msg("UUID 格式不正确")
			} else {
				uuid = append(uuid, uint32(parseInt))
			}
		}
		param.UUIDs = uuid
	}

	images, cnt, err := s.Srv.SearchImages(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	res := make([]model.ImageResponse, 0)
	for i := range images {
		ans := model.ImageResponse{
			ID:           images[i].ID,
			Digest:       images[i].Digest,
			NodeIP:       images[i].NodeIP,
			FullRepoName: images[i].FullRepoName,
			Tags:         images[i].Tags,
			ImageType:    images[i].ImageType,
			FromType:     images[i].FromType,
			NodeHostname: images[i].NodeHostname,
			RegistryID:   images[i].RegistryID,
			ImageUUID:    images[i].ImageUUID,
		}
		if images[i].Registry != nil {
			ans.Library = images[i].Registry.Url
			ans.RegistryDeletedAt = images[i].Registry.DeletedAt
			ans.RegistryName = images[i].Registry.Name
		}

		res = append(res, ans)
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *Scanner) VerifyExistence(ctx *gin.Context) {

	filter := model.GetFilter(ctx)

	param := component.SearchImageParam{}
	uuids := ctx.Query("uuids")

	uuid := make([]uint32, 0)
	split := strings.Split(uuids, ",")
	for i := range split {
		if parseInt, err := strconv.ParseInt(split[i], 10, 64); err != nil {
			logging.Get().Err(err).Msg("UUID 格式不正确")
		} else {
			uuid = append(uuid, uint32(parseInt))
		}
	}
	if len(uuid) == 0 {
		response.JSONError(ctx, fmt.Errorf("not get uuids"))
		return
	}
	param.UUIDs = uuid

	images, _, err := s.Srv.SearchImages(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := make(map[uint32]bool)
	for i := range uuid {
		res[uuid[i]] = false
	}

	for i := range images {
		res[images[i].ImageUUID] = true
	}
	type exit struct {
		VerifyExistence map[uint32]bool `json:"verifyExistence"`
	}
	response.JSONOK(ctx, response.WithItem(exit{VerifyExistence: res}))
}

func (s *Scanner) ExistenceCount(ctx *gin.Context) {
	filter := model.GetFilter(ctx)
	param := component.SearchImageParam{Fields: []string{"id", "image_uuid"}}
	uuids := ctx.Query("uuids")
	uuid := make([]uint32, 0)

	split := strings.Split(uuids, ",")
	for i := range split {
		if parseInt, err := strconv.ParseInt(split[i], 10, 64); err != nil {
			logging.Get().Err(err).Msg("UUID 格式不正确")
		} else {
			uuid = append(uuid, uint32(parseInt))
		}
	}
	if len(uuid) == 0 {
		response.JSONError(ctx, fmt.Errorf("not get uuids"))
		return
	}
	param.UUIDs = uuid

	images, _, err := s.Srv.SearchImages(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := make(map[uint32]bool)
	for i := range param.UUIDs {
		res[param.UUIDs[i]] = false
	}
	for i := range images {
		res[images[i].ImageUUID] = true
	}
	exit, all := 0, 0

	for _, v := range res {
		if v {
			exit++
		}
		all++
	}
	type exits struct {
		Exit int `json:"exit"`
		All  int `json:"all"`
	}

	response.JSONOK(ctx, response.WithItem(exits{Exit: exit, All: all}))
}

// ListImgLayers 镜像的回溯信息
// @Summary ListImgLayers
// @Title 镜像的回溯信息
// @Author liuqiang@tensorsecurity.cn
// @Description 获取镜像各层级的信息
// @Tags scan image
// @Param imgDigest query int64 true "imgDigest"
// @Success 200 {object} ApiWithItem{data=ApiItem{items=[]model.ReportImgBackInfo}}
// @Router	/api/v1/images/:imgID/layers [get]
func (s *Scanner) ListImgLayers(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Param("imgID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusExpectationFailed, err))
		return
	}

	images, err := s.Srv.ListImgLayers(ctx, imageID, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(images))
}

// ImgLayerInfo 镜像的回溯信息
// @Summary ImgLayerInfo
// @Title 镜像的回溯信息
// @Author liuqiang@tensorsecurity.cn
// @Description 获取镜像各层级的信息
// @Tags scan image
// @Param layerDigest query string true "layerDigest"
// @Success 200 {object} ApiWithItem{data=ApiItem{items=model.ScanLayer}}
// @Router	/api/v1/layers/:layerDigest/layers [get]
func (s *Scanner) ImgLayerInfo(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Param("imageId"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("not fond imageID"))
		return
	}

	layerDigest := ctx.Param("layerDigest")

	info, err := s.Srv.ImgLayerInfo(ctx, imageID, layerDigest, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*info))
}

func NewScannerAPISrv(
	srv component.ScannerSrv,
	vulnSrv component.VulnServiceInterface,
	imageSrv component.ImageSrvInterface) *Scanner {
	return &Scanner{
		Srv:      srv,
		VulnSrv:  vulnSrv,
		ImageSrv: imageSrv,
	}
}

// ListBaseImage 基础镜像列表
// @Summary ListBaseImage
// @Title 基础镜像列表
// @Author liuqiang@tensorsecurity.cn
// @Description 基础镜像列表
// @Tags image reject
// @Param search query string false "搜索关键词"
// @Success 200 {object} ApiWithItem{data=ApiItem{items=[]model.ImageResponse{}}}
// @Router	/api/v1/images/bases [get]
func (s *Scanner) ListBaseImage(ctx *gin.Context) {
	filter := model.GetFilter(ctx)
	// 排序对性能影响很大
	// filter.SortFiled = "full_repo_name"
	// filter.SortBy = "asc"
	search := ctx.Query("search")
	images, cnt, err := s.ImageSrv.ListImageWithScanInfo(ctx,
		model.ImageListParam{
			Keyword:   search,
			FromType:  model.ImageFromRegistry,
			ImageAttr: model.ImageAttrParam{ImageType: model.BaseImageTypeString},
		}, filter)

	// component.SearchImageWithScanParam{ImageType: model.BaseImageTypeString, SearchWord: search, FromType: model.UserRegistry}, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(images),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset),
	)
}

// ListAppToBaseImage 获取应用镜像的基础镜像列表
// @Summary ListAppToBaseImage
// @Title 获取应用镜像的基础镜像列表
// @Author liuqiang@tensorsecurity.cn
// @Description 获取应用镜像的基础镜像列表
// @Tags image reject
// @Param imageID path int true "镜像ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{items=[]model.ImageResponse{}}}
// @Router	/api/v1/images/app/:imageID/bases [get]
func (s *Scanner) ListAppToBaseImage(ctx *gin.Context) {
	start := time.Now().UnixNano() / 1000
	logging.Get().Info().Msgf("ListBaseImageOfApp start:%d", start)
	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	filter := model.GetFilter(ctx)
	images, cnt, err := s.Srv.ListBaseImageOfApp(ctx, imageID, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 数据规整
	res := make([]model.ImageResponse, 0)
	for i := range images {
		res = append(res, model.ImageToImageResponse(images[i]))
	}
	logging.Get().Info().Msgf("ListBaseImageOfApp end:%d,cost:%d", time.Now().UnixNano()/1000, time.Now().UnixNano()/1000-start)
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset),
	)
}

// QueryEnvInStrategy 获取对应环境变量还未被多少策略引用
// @Summary QueryEnvInStrategy
// @Title 获取对应环境变量还未被多少策略引用
// @Author guolingkai@tensorsecurity.cn
// @Description 获取对应环境变量还未被多少策略引用
// @Tags image reject
// @Param envName path string true "环境变量名称"
// @Success 200 {object} ApiWithItem{data=ApiItem{items=[]model.ScanStrategy{}}}
// @Router	/api/v1/images/env/:envName [get]
func (s *Scanner) QueryEnvInStrategy(ctx *gin.Context) {
	envName := ctx.Param("envName")
	if envName == "" {
		response.JSONError(ctx, fmt.Errorf("envName is null"))
		return
	}
	res, err := s.Srv.GetStrategyForEnv(ctx, envName)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

// SetEnvToStrategy 设置环境变量进某个策略
// @Summary SetEnvToStrategy
// @Title 设置环境变量进某个策略
// @Author guolingkai@tensorsecurity.cn
// @Description 设置环境变量进某个策略
// @Tags image reject
// @Param policy path string true "策略ID集合，逗号分隔"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/images/env/:envName [put]
func (s *Scanner) SetEnvToStrategy(ctx *gin.Context) {
	envName := ctx.Param("envName")
	policyStr := ctx.Query("policy")
	var policyIds []int64
	policyStrs := strings.Split(policyStr, ",")
	for k := range policyStrs {
		tmpID, err := strconv.ParseInt(policyStrs[k], 10, 64)
		if err != nil {
			logging.Get().Err(err).Msg("ParseInt error SetEnvToStrategy")
		}
		policyIds = append(policyIds, tmpID)
	}
	if len(policyIds) == 0 {
		response.JSONError(ctx, fmt.Errorf("has not policyID parse success"))
		return
	}

	err := s.Srv.SetEnvToStrategy(ctx, envName, policyIds)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: envName,
		ID:   envName,
		Link: "api/v2/containerSec/scanner/images/env/" + envName,
	}))
}

// ListBaseToAppImage 获取基础镜像的应用镜像列表
// @Summary ListBaseToAppImage
// @Title 获取基础镜像的应用镜像列表
// @Author liuqiang@tensorsecurity.cn
// @Description 获取基础镜像的应用镜像列表
// @Tags image reject
// @Param imageID path int true "镜像ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{items=[]model.ImageResponse{}}}
// @Router	/api/v1/images/base/:imageID/apps [get]
func (s *Scanner) ListBaseToAppImage(ctx *gin.Context) {
	start := time.Now().UnixNano() / (1000 * 1000)
	logging.Get().Info().Msgf("ListAppImageOfBase start:%d", start)
	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	filter := model.GetFilter(ctx)
	images, cnt, err := s.Srv.ListAppImageOfBase(ctx, imageID, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 数据规整
	res := make([]model.ImageResponse, 0)
	for i := range images {
		res = append(res, model.ImageToImageResponse(images[i]))
	}
	logging.Get().Info().Msgf("ListAppImageOfBase end:%d,cost:%d", time.Now().UnixNano()/(1000*1000), time.Now().UnixNano()/(1000*1000)-start)
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset),
	)
}

// CreateBaseImage 创建基础镜像
// @Summary CreateBaseImage
// @Title 创建基础镜像
// @Author liuqiang@tensorsecurity.cn
// @Description 创建基础镜像
// @Tags image reject
// @Param body body []int true "镜像ID列表"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/images/bases [post]
func (s *Scanner) CreateBaseImage(ctx *gin.Context) {
	type ids struct {
		ImageIds []int64 `json:"image_ids"`
	}
	body := new(ids)
	if err := ctx.BindJSON(body); err != nil {
		response.JSONError(ctx, err)
		return
	}
	scan, _, err := s.Srv.SearchImages(ctx, component.SearchImageParam{ImageIds: body.ImageIds}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	if err := s.Srv.UpdateImageType(ctx, body.ImageIds, model.BaseImageType); err != nil {
		response.JSONError(ctx, err)
		return
	}

	names := make([]string, len(scan))
	for i := range scan {
		names[i] = fmt.Sprintf("%s:%s", scan[i].FullRepoName, scan[i].Tags)
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: strings.Join(names, ","),
		Link: "api/v2/containerSec/scanner/images/bases",
	}))
}

// DeleteBaseImage 删除基础镜像
// @Summary DeleteBaseImage
// @Title 删除基础镜像
// @Author liuqiang@tensorsecurity.cn
// @Description 删除基础镜像
// @Tags image reject
// @Param imageID path int true "镜像ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/images/base/:imageID [delete]
func (s *Scanner) DeleteBaseImage(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if err := s.Srv.UpdateImageType(ctx, []int64{imageID}, model.AppImageType); err != nil {
		response.JSONError(ctx, err)
		return
	}
	detail, err := s.Srv.GetImageDetail(ctx, imageID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: fmt.Sprintf("%s:%s", detail.FullRepoName, detail.Tags),
		ID:   strconv.Itoa(int(imageID)),
		Link: "api/v2/containerSec/scanner/images/base/" + strconv.Itoa(int(imageID)),
	}))
}

func (s *Scanner) ImageOverview(ctx *gin.Context) {
	type Body struct {
		UUIDS []uint32 `json:"uuids"`
	}
	body := new(Body)
	if err := ctx.BindJSON(body); err != nil {
		response.JSONError(ctx, fmt.Errorf("未解析到image uuid"))
		return
	}
	overview, err := s.Srv.ImageOverview(ctx, body.UUIDS)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithTotalItems(int64(len(overview))), response.WithItems(overview))
}

// GetScanTaskList 获取扫描任务记录列表
// @Summary 扫描任务
// @Title 获取扫描任务记录列表
// @Author liuyang@tensorsecurity.cn
// @Description 获取扫描任务记录列表
// @Tags scan task
// @Param offset query integer true "int"
// @Param limit query integer true "int"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/tasks [get]
func (s *Scanner) GetScanTaskList(ctx *gin.Context) {
	filter := model.GetFilterWithDefaultValue(ctx)
	filter.SortFiled = "group_id"
	filter.SortBy = consts.SortByDesc

	data, count, err := s.Srv.GetScanTaskList(ctx, filter)
	if err != nil {
		response.JSONError(ctx, errors.New("获取扫描任务记录失败"))
		return
	}

	// 多集群适配，为了前端少改动，把groupID和ID对换
	for i := range data {
		data[i].ID, data[i].GroupID = data[i].GroupID, data[i].ID
	}

	response.JSONOK(ctx,
		response.WithTotalItems(count),
		response.WithItems(data),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// GetScanSubTaskList 获取某个任务的子任务列表
// @Summary 扫描任务
// @Title 获取某个任务的子任务列表
// @Author liuyang@tensorsecurity.cn
// @Description 获取某个任务的子任务列表
// @Tags scan task
// @Param offset query integer true "int"
// @Param limit query integer true "int"
// @Param id path integer true "任务的ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/tasks/:id/subtasks [get]
func (s *Scanner) GetScanSubTaskList(ctx *gin.Context) {
	groupID, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("无效的taskId: %s", ctx.Param("id")))
		return
	}

	status := util.GetInt64SliceFromQuery(ctx, "status")

	filter := model.GetFilter(ctx)
	// 默认按如下排序
	filter.OrderByColumns = append(filter.OrderByColumns, clause.OrderByColumn{Column: clause.Column{Name: "status"}, Desc: true})
	filter.OrderByColumns = append(filter.OrderByColumns, clause.OrderByColumn{Column: clause.Column{Name: "started_at"}, Desc: true})
	data, count, err := s.Srv.GetScanSubTaskList(ctx, groupID, status, filter)
	if err != nil {
		response.JSONError(ctx, errors.New("获取扫描子任务记录失败"))
		return
	}
	res := make([]apimodel.SubTask, 0)
	for i := range data {
		sub := apimodel.SubTask{
			ID:         data[i].ID,
			TaskID:     data[i].TaskID,
			ImageID:    data[i].ImageID,
			Result:     data[i].Result,
			ErrMsg:     data[i].ErrMsg,
			ErrNo:      data[i].ErrNo,
			ErrMsgEnu:  data[i].ErrMsgEnu,
			CreatedAt:  data[i].CreatedAt,
			StartedAt:  data[i].StartedAt,
			UpdatedAt:  data[i].UpdatedAt,
			FinishedAt: data[i].FinishedAt,
			HeartBeat:  data[i].HeartBeat,
			RetryCount: data[i].RetryCount,
			// 这里为了兼容 subtask表的status是从0开始，ivan_scanner_image_list表中的flag是从11位开始
			Status:       model.GetSubTaskScanStatusString(data[i].Status + 11),
			FullRepoName: data[i].FullRepoName,
			Tag:          data[i].Tag,
			Library:      data[i].Library,
		}
		res = append(res, sub)
	}

	response.JSONOK(ctx,
		response.WithTotalItems(count),
		response.WithItems(res),
		response.WithStartIndex(filter.Offset),
		response.WithItemsPerPage(filter.Limit))
}

// UpdateTaskStatus 修改某个任务的状态
// @Summary 扫描任务
// @Title 修改某个任务的状态
// @Author liuyang@tensorsecurity.cn
// @Description 修改某个任务的状态
// @Tags scan task
// @Param id path integer true "任务的ID"
// @Param status body json true "修改后的状态"
// @Success 200 {object} ApiWithItem{data=ApiItem{}}
// @Router	/api/v1/tasks/:id/status [put]
func (s *Scanner) UpdateTaskStatus(ctx *gin.Context) {
	type S struct {
		Status uint8 `json:"status"`
	}

	var data S
	err := ctx.Bind(&data)
	if err != nil {
		response.JSONError(ctx, errors.Wrap(err, "获取参数失败"))
		return
	}

	taskGroupID, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("无效的taskId: %s", ctx.Param("id"))))
		return
	}

	err = s.Srv.UpdateScanTaskStatus(ctx, taskGroupID, data.Status)
	if err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: fmt.Sprintf("task %d", taskGroupID),
		ID:   strconv.Itoa(int(taskGroupID)),
		Link: "api/v2/containerSec/scanner/tasks/" + strconv.Itoa(int(taskGroupID)) + "/status",
	}))
}

func (s *Scanner) GetOpenapiDoc(ctx *gin.Context) {
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
	if strings.ToLower(ctx.GetHeader("Accept-Language")) == "en" ||
		strings.ToLower(ctx.GetHeader("accept-language")) == "en" {
		res = resEN
	}

	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(int64(len(res))))
}

func (s *Scanner) GetFileChecker(ctx *gin.Context) {
	fileName := ctx.Query("name")
	if fileName == "file-checker" {
		ctx.File("/config/file-checker")
		return
	} else if fileName == "dp.so" {
		ctx.File("/config/dp.so")
		return
	} else {
		ctx.Status(500)
		return
	}
}

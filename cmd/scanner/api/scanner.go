package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type Scanner struct {
	Srv component.ScannerSrv
	log *logging.Logger
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
	containerInfo := []model.RejectOnlineMoniterImage{}
	if err := ctx.BindJSON(&containerInfo); err != nil {
		s.log.WithContext(ctx).Errorf(err, "BindJSON error")
		return
	}
	if len(containerInfo) == 0 {
		s.log.WithContext(ctx).Infof("收到TickOnlineScan,空数据")
		return
	}

	s.log.WithContext(ctx).Infof("收到TickOnlineScan,from_type:%s,image:%s", containerInfo[0].FromType, containerInfo[0].Image)
	flag := s.Srv.TickOnlineScan(ctx, containerInfo)
	type tmpRes struct {
		Flag bool `json:"flag"`
	}
	res := tmpRes{}
	res.Flag = flag
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
// @Router /api/v1/vulns/query/:name [get]
func (s *Scanner) ListImageInfoFromVuln(ctx *gin.Context) {
	name := ctx.Param("name")
	res, err := s.Srv.GetImagesFromVuln(ctx, name)
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
// @Router /api/v1/vulns/detail/:name [get]
func (s *Scanner) ScannedByVulnDetails(ctx *gin.Context) {
	name := ctx.Param("name")
	res, err := s.Srv.GetVulnDetails(ctx, name)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(res))
}

// ListScannedByVulnList
// all
// @Summary all
// @Title all
// @Author guolingkai@tensorsecurity.cn
// @Description 获取漏洞列表
// @Tags Vuln
// @Param search query string false "for vuln like "
// @Param offset query int true "int"
// @Param limit query int true "int"
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.VulnList{}}}
// @Router	/api/v1/vulns/all [get]
func (s *Scanner) ListScannedByVulnList(ctx *gin.Context) {
	search := ctx.Query("search")
	if len(search) > 64 {
		response.JSONError(ctx, errors.New("the maximum value is exceeded"))
		return
	}
	offset, _ := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	limit, _ := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	vulns, cnt, err := s.Srv.SearchVulns(ctx, search, &model.Filter{
		PageSize: limit,
		Offset:   offset,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(vulns),
		response.WithTotalItems(int64(cnt)),
		response.WithItemsPerPage(limit),
		response.WithStartIndex(offset))
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
	res, _ := s.Srv.GetVulnOverView(ctx)
	response.JSONOK(ctx, response.WithItem(res), response.WithExportFileStatus(0))
}

// GetScanStatus
// @Summary scanStatus
// @Title scanStatus
// @Author guolingkai@tensorsecurity.cn
// @Description 获取镜像列表的扫描状态
// @Tags scan image
// @Success 200 {object} ApiWithItem{data=ApiItem{item=ScanStatusRes{harborStatus=harbor.ScanAllStatus{metrics=harbor.ScanAllStatusMetrics}}}}
// @Router	/api/v1/scan/harbor/GetScanStatus [get]
func (s *Scanner) GetScanStatus(ctx *gin.Context) {
	type respT struct {
		ScanAllStatus harbor.ScanAllStatus `json:"harborStatus"`
		IsAborted     bool                 `json:"isAborted"` // if true, we are currently in the process of aborting harbor scan all job. Abort button should be disabled.
	}
	time.Sleep(1 * time.Second)
	status := s.Srv.GetScanAllStatus(ctx)
	resp := respT{ScanAllStatus: status, IsAborted: false}
	response.JSONOK(ctx, response.WithItem(resp))
}

// ScanAllNow
// @Summary ScanAllNow
// @Title ScanAllNow
// @Author guolingkai@tensorsecurity.cn
// @Description 扫描全部列表中的镜像
// @Tags scan image
// @Success 200 {object} ApiWithItem{data{}}
// @Router	/api/v1/scan/harbor/scanAllNow [post]
func (s *Scanner) ScanAllNow(ctx *gin.Context) {
	registerUrl := ctx.Query("fromUrl")
	// asynchronous execution, no matter what return no error
	go func() {
		if err := s.Srv.ScanAllNow(ctx, registerUrl); err != nil {
			log.Err(err).Msg("scan all error")
		}
	}()

	response.JSONOK(ctx)
}

// StartScanOne
// @Summary ScanOne
// @Title ScanOne
// @Author guolingkai@tensorsecurity.cn
// @Description 扫描列表中某一个镜像，参数为单个id
// @Tags scan image
// @Param body body OnlyIdRes true "Json数据"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=OnlyStatusRes{}}}
// @Router	/api/v1/scan/scanone [post]
func (s *Scanner) StartScanOne(ctx *gin.Context) {
	type resp struct {
		Status string `json:"status"`
	}
	type tmpRecv struct {
		ImgId int64 `json:"id"`
	}
	tmp := tmpRecv{}
	// json := make(map[string]interface{})
	if err := ctx.BindJSON(&tmp); err != nil {
		response.JSONError(ctx, err)
		return
	}
	// fmt.Println("收获JSON为:", json)
	err := s.Srv.TickScanOne(ctx, tmp.ImgId, "", consts.ScanTaskComeFromWeb)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(resp{Status: "OK"}))
}

// ListRegistry
// @Summary 获取仓库列表
// @Title 获取仓库列表
// @Author guolingkai@tensorsecurity.cn
// @Description 获取registry列表信息
// @Tags registry
// @Param no_policy query bool true "是否需要配置策略的仓库"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=OnlyAccountRes{}}}
// @Router	/api/v1/register/registries [get]
func (s *Scanner) ListRegistry(ctx *gin.Context) {
	noRejectPolicy, _ := strconv.ParseBool(ctx.Query("no_policy"))

	registries, _, err := s.Srv.ListRegistry(ctx, noRejectPolicy)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	urls := make([]string, 0)
	for _, reg := range registries {
		if reg.UseType != model.RegistryUseTypeBuff {
			urls = append(urls, reg.Url)
		}
	}
	response.JSONOK(ctx, response.WithItems(urls))
}

// GetRegistry
// @Summary 获取指定仓库的具体信息
// @Title 获取指定仓库的具体信息
// @Author guolingkai@tensorsecurity.cn
// @Description 获取registry具体信息
// @Tags registry
// @Param usetype query string true "仓库类型"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=OnlyAccountRes{}}}
// @Router	/api/v1/register/registry [get]
func (s *Scanner) GetRegistry(ctx *gin.Context) {
	usetype := ctx.Query("usetype")

	registries, _, err := s.Srv.ListRegistry(ctx, false)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	type res struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	for _, reg := range registries {
		ans := res{
			Username: reg.Username,
			Password: reg.PasswordString,
		}
		if strconv.Itoa(reg.UseType) == usetype {
			response.JSONOK(ctx, response.WithItem(ans))
			return
		}
	}
	response.JSONError(ctx, errors.New("no library"))
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
	fmt.Printf("接收到的信息为%v\n", tmp)
	resp, err := s.Srv.ScanOneForCICDResult(ctx, tmp)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if resp != nil {
		// 整理数据
		resp.Vulu = make([][]string, 0)
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
		if resp.ImageDetail != nil && len(resp.ImageDetail.ImageScanVuln.TopVulns) > 0 {
			resp.Vulu = append(resp.Vulu, []string{"漏洞编号", "严重程度", "软件包", "软件版本"})
			for _, vu := range resp.ImageDetail.ImageScanVuln.TopVulns {
				resp.Vulu = append(resp.Vulu, []string{vu.ID, vu.Severity, vu.FeatureName, vu.FeatureVersion})
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
			resp.Virus = append(resp.Virus, []string{"文件名", "文件路径", "评分", "代码详情"})
			for _, vu := range resp.ImageDetail.ImageScanWebshell {
				resp.Webshell = append(resp.Webshell, []string{vu.Filename, vu.Filepath, strconv.Itoa(int(vu.Score)), strings.Join(vu.Codes, ",")})
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
	s.log.WithContext(ctx).Infof("CICD 收到的请求,image:%s,Insecure:%t", tmp.Image, tmp.Insecure)

	hasHttp := strings.Contains(tmp.Image, "http://")
	hasHttps := strings.Contains(tmp.Image, "https://")
	if !hasHttps && !hasHttp {
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

// GetScanOneStatus
// @Summary GetScanOneStatus
// @Title 获取单个镜像的扫描状态
// @Author guolingkai@tensorsecurity.cn
// @Description 获取单个镜像的扫描状态
// @Tags scan image
// @Param id query int true "Image ID"
// @Success 200 {object} ApiWithItem{data=ApiItem{item=model.ScanOneStatusResponse{}}}
// @Router	/api/v1/scan/harbor/scanOneStatus [get]
func (s *Scanner) GetScanOneStatus(ctx *gin.Context) {
	imgId, err := strconv.ParseInt(ctx.Query("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, errors.New("no image id"))
		return
	}
	res, err := s.Srv.GetScanOneStatus(ctx, imgId, "")
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*res))
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
	registerUrl := ctx.Query("fromUrl")

	view, err := s.Srv.GetImageOverView(ctx, registerUrl)
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
	imgId, err := strconv.ParseInt(ctx.Query("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, errors.New("no image id"))
	}
	img, err := s.Srv.GetImageDetail(ctx, imgId)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*img))
}

// ListScannedByImageList
// @Summary ListScannedByImageList
// @Title ListScannedByImageList
// @Author guolingkai@tensorsecurity.cn
// @Description 获取单个镜像的扫描状态
// @Tags scan image
// @Param search query string false "for image like "
// @Param kind query int false "0:vuln,1:vrius,2:senstive"
// @Param online query bool true "is online?"
// @Param offset query int true "int"
// @Param limit query int true "int"
// @Success 200 {object} ApiWithItem{data=ApiItems{items=[]model.ImageResponse{}}}
// @Router	/api/v1/scan/reportsByImageList [get]
func (s *Scanner) ListScannedByImageList(ctx *gin.Context) {
	search := ctx.Query("search")
	if len(search) > 64 {
		response.JSONError(ctx, errors.New("the maximum value is exceeded"))
		return
	}
	kind := ctx.Query("kind")
	sortBy := ctx.Query("sortOrder")
	imageType := ctx.Query("imageType")
	library := ctx.Query("library")

	offset, _ := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	limit, _ := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	online, _ := strconv.ParseBool(ctx.Query("online"))

	logging.GetLogger().Info().Msg(fmt.Sprintf("get kind:%s", kind))
	images, cnt, err := s.Srv.SearchImages(ctx, component.SearchImagesParam{
		SearchWord:      search,
		Kind:            kind,
		IsOnline:        online,
		HasQuestionInfo: true,
		Library:         library,
		ImageType:       imageType,
	}, &model.Filter{
		PageSize: limit,
		SortBy:   sortBy,
		Offset:   offset,
	})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("SearchImages Err")
		response.JSONError(ctx, fmt.Errorf("SearchImages error"))
		return
	}
	// 数据规整
	res := make([]model.ImageResponse, 0)
	for i := range images {
		res = append(res, model.ImageToImageResponse(images[i]))
	}
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(limit),
		response.WithStartIndex(offset))
}

func (s *Scanner) CheckProjectAndCreateIfNotExist(ctx *gin.Context) {
	projectName := ctx.Param("projectName")
	library := ctx.Query("library")
	if !strings.Contains(library, "http") {
		library = "https://" + library
	}

	err := s.Srv.CheckProjectAndCreateIfNotExist(ctx, library, projectName)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	type Resp struct {
		Existed bool `json:"existed"`
	}
	ctx.JSON(http.StatusOK, Resp{Existed: true})
}

// ListImgLayers 镜像的回溯信息
// @Summary ListImgLayers
// @Title 镜像的回溯信息
// @Author liuqiang@tensorsecurity.cn
// @Description 获取镜像各层级的信息
// @Tags scan image
// @Param imgDigest query string true "imgDigest"
// @Success 200 {object} ApiWithItem{data=ApiItem{items=[]model.ReportImgBackInfo}}
// @Router	/api/v1/images/:imgDigest/layers [get]
func (s *Scanner) ListImgLayers(ctx *gin.Context) {
	imgDigest := ctx.Param("imgDigest")

	images, err := s.Srv.ListImgLayers(ctx, imgDigest, nil)
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
// @Router	/api/v1/layers/:imgDigest/layers [get]
func (s *Scanner) ImgLayerInfo(ctx *gin.Context) {
	layerDigest := ctx.Param("layerDigest")

	image, err := s.Srv.ImgLayerInfo(ctx, layerDigest, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*image))
}

func NewScannerApiSrv(srv component.ScannerSrv) *Scanner {
	return &Scanner{
		Srv: srv,
		log: logging.GetLogger(),
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
// @Router	/api/v1/images/base [get]
func (s *Scanner) ListBaseImage(ctx *gin.Context) {
	filter := model.GetFilter(ctx)
	search := ctx.Query("search")
	images, cnt, err := s.Srv.SearchImages(ctx, component.SearchImagesParam{ImageType: consts.BaseImage, HasQuestionInfo: true, SearchWord: search}, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	res := make([]model.ImageResponse, 0)
	for i := range images {
		res = append(res, model.ImageToImageResponse(images[i]))
	}
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(cnt))
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
	logging.GetLogger().Info().Msgf("ListBaseImageOfApp start:%d", start)
	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	images, err := s.Srv.ListBaseImageOfApp(ctx, imageID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 数据规整
	res := make([]model.ImageResponse, 0)
	for i := range images {
		res = append(res, model.ImageToImageResponse(images[i]))
	}
	logging.GetLogger().Info().Msgf("ListBaseImageOfApp end:%d,cost:%d", time.Now().UnixNano()/1000, time.Now().UnixNano()/1000-start)
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(int64(len(res))))
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
	logging.GetLogger().Info().Msgf("ListAppImageOfBase start:%d", start)
	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	images, err := s.Srv.ListAppImageOfBase(ctx, imageID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 数据规整
	res := make([]model.ImageResponse, 0)
	for i := range images {
		res = append(res, model.ImageToImageResponse(images[i]))
	}
	logging.GetLogger().Info().Msgf("ListAppImageOfBase end:%d,cost:%d", time.Now().UnixNano()/(1000*1000), time.Now().UnixNano()/(1000*1000)-start)
	response.JSONOK(ctx, response.WithItems(res), response.WithTotalItems(int64(len(res))))
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

	updater := map[string]interface{}{"image_type": consts.BaseImageType}
	if err := s.Srv.UpdateImage(ctx, component.SearchImagesParam{ImageIds: body.ImageIds}, updater); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
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
	body := map[string]interface{}{"image_type": consts.AppImageType}
	if err := s.Srv.UpdateImage(ctx, component.SearchImagesParam{ImageId: imageID}, body); err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

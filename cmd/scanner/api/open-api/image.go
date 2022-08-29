package openapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	apimodel "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageOpenAPISvc struct {
	ImageSrv      component.ImageSrvInterface
	ScannerSrv    component.ScannerSrv
	RegistrySrv   component.RegistrySrvInterface
	ScanConfigSrv component.ScanConfigSrvInterface
}

func NewScannerOpenAPISrv(
	srv component.ScannerSrv,
	registrySrv component.RegistrySrvInterface,
	scanConfigSrv component.ScanConfigSrvInterface,
	imageSrv component.ImageSrvInterface,
) *ImageOpenAPISvc {
	return &ImageOpenAPISvc{
		ScannerSrv:    srv,
		ImageSrv:      imageSrv,
		RegistrySrv:   registrySrv,
		ScanConfigSrv: scanConfigSrv,
	}
}

// open-api镜像列表 discard
func (s *ImageOpenAPISvc) ListImages(ctx *gin.Context) {
	search := ctx.Query("keyword")
	if len(search) > 64 {
		response.JSONError(ctx, errors.New("the maximum value is exceeded"))
		return
	}
	kind := ctx.Query("securityIssue")
	imageType := ctx.Query("imageType")
	online := ctx.Query("online")
	trusted := ctx.Query("trusted")
	hasFixedVulu := ctx.Query("hasFixedVuln")
	isReinforce := ctx.Query("reinforced")
	nodeHostname := ctx.Query("nodeHostname")

	param := component.SearchImageWithScanParam{
		SearchWord:   search,
		Kind:         kind,
		Online:       online,
		ImageType:    imageType,
		Trusted:      trusted,
		HasFixedVulu: hasFixedVulu,
		IsReinforce:  isReinforce,
		NodeHostname: nodeHostname,
	}
	fromTypeString := ctx.Query("fromType")
	if fromTypeString == model.ImageFromNode {
		param.FromType = model.NodeBuffRegistry
	} else if fromTypeString == model.ImageFromRegistry {
		param.FromType = model.UserRegistry
	}

	filter := model.GetFilterWithDefaultValue(ctx)
	filter.SortFiled = "full_repo_name"
	filter.SortBy = "asc"

	images, cnt, err := s.ScannerSrv.SearchImageWithScan(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	res := make([]apimodel.ImageListResponse, 0)
	for i := range images {
		im := apimodel.ImageListResponse{
			ID:            images[i].ID,
			LastScannedAt: images[i].CompleteTime,
			Digest:        images[i].Digest,
			HasFixedVuln:  images[i].HasFixedVulu,
			ImageType:     images[i].FromType,
			Reinforced:    images[i].IsReinforce,
			NodeHostname:  images[i].NodeHostname,
			NodeIP:        images[i].NodeIP,
			Online:        images[i].Online,
			SecurityIssue: make([]int, 0),
			RegistryName:  images[i].RegistryName,
			RegistryURL:   images[i].Library,
			RiskScore:     images[i].RiskScore,
			ScanStatus:    images[i].ScanStatus,
			Image:         fmt.Sprintf("%s:%s", images[i].FullRepoName, images[i].Tags),
			Trusted:       images[i].Trusted,
		}
		for j := range images[i].Questions {
			im.SecurityIssue = append(im.SecurityIssue, images[i].Questions[j].ID)
		}
		if images[i].FromType == model.NodeBuffRegistry {
			im.FromType = model.ImageFromNode
		} else if images[i].FromType == model.UserRegistry {
			im.FromType = model.ImageFromRegistry
		}

		res = append(res, im)
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// open-api镜像列表
func (s *ImageOpenAPISvc) SearchImages(ctx *gin.Context) {
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

func (s *ImageOpenAPISvc) GetRegistryProject(ctx *gin.Context) {
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

// open-api镜像统计
func (s *ImageOpenAPISvc) ImageStatistic(ctx *gin.Context) {
	fromTypeString := ctx.Query("fromType")
	if fromTypeString == "" {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no fromType")))
		return
	}
	fromType := model.UserRegistry

	if fromTypeString == model.ImageFromNode {
		fromType = model.NodeBuffRegistry
	} else if fromTypeString == model.ImageFromRegistry {
		fromType = model.UserRegistry
	}

	view, err := s.ScannerSrv.GetImageOverView(ctx, int64(fromType))
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	res := apimodel.OverView{
		ImageTotal:  view.ImageTotal,
		OnlineTotal: view.OnlineTotal,
		Total: apimodel.SafeOver{
			Vulns:                view.Sum.VULN,
			Viruses:              view.Sum.VIRUS,
			SensitiveFile:        view.Sum.SENSITIVE,
			Webshell:             view.Sum.Webshell,
			ExceptEnvs:           view.Sum.Envs,
			NonCompliantSoftware: view.Sum.Software,
			NotAllowedLicense:    view.Sum.License,
			PrivilegedBoot:       view.Sum.PrivilegedBoot,
		},
		Online: apimodel.SafeOver{
			Vulns:                view.Online.VULN,
			Viruses:              view.Online.VIRUS,
			SensitiveFile:        view.Online.SENSITIVE,
			Webshell:             view.Online.Webshell,
			ExceptEnvs:           view.Online.Envs,
			NonCompliantSoftware: view.Online.Software,
			NotAllowedLicense:    view.Online.License,
			PrivilegedBoot:       view.Online.PrivilegedBoot,
		},
	}
	response.JSONOK(ctx, response.WithItem(res))
}

// open-api 镜像详情
func (s *ImageOpenAPISvc) GetImageDetails(ctx *gin.Context) {
	registryName := ctx.Query("registryName")
	imageName := ctx.Query("imageName")

	if len(registryName) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no registy name:%s", registryName)))
		return
	}
	if len(imageName) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no image name:%s", registryName)))
		return
	}
	repoName, tag, err := ParseImageName(imageName)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	registries, _, err := s.RegistrySrv.SearchRegistry(ctx, component.SearchRegistryParam{
		Name:    registryName,
		UseType: model.UserRegistry,
	}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(registries) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond registry:%s", registryName)))
		return
	}

	image, _, err := s.ScannerSrv.SearchImages(ctx, component.SearchImageParam{
		FullRepoName: repoName,
		Tags:         tag,
		RegistryID:   registries[0].ID,
	}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(image) == 0 {
		response.JSONError(ctx, fmt.Errorf("not fond image:%s", imageName))
		return
	}

	img, err := s.ScannerSrv.GetImageDetail(ctx, image[0].ID)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := apimodel.ImageDetail{
		Digest:         img.Digest,
		Image:          fmt.Sprintf("%s:%s", img.FullRepoName, img.Tags),
		SensitiveFile:  make([]string, 0),
		Viruses:        img.ImageScanVirus,
		Envs:           make([]apimodel.SummaryEnv, 0),
		Webshell:       img.ImageScanWebshell,
		Vulns:          make([]apimodel.Vuln, 0),
		ImageType:      img.ImageType,
		Reinforced:     img.IsReinforce,
		NodeHostname:   img.NodeHostname,
		NodeIP:         img.NodeIP,
		PrivilegedBoot: img.PrivilegedBoot,
		Size:           img.Size,
	}
	if img.Registry != nil {
		res.RegistryURL = img.Registry.Url
	}
	if img.FromType == model.UserRegistry {
		res.FromType = model.ImageFromRegistry
	} else if img.FromType == model.NodeBuffRegistry {
		res.FromType = model.ImageFromRegistry
	}

	for i := range img.ImageScanEnv {
		res.Envs = append(res.Envs, apimodel.SummaryEnv{
			EnvName:    img.ImageScanEnv[i].EnvName,
			EnvValue:   img.ImageScanEnv[i].EnvValue,
			IsAbnormal: img.ImageScanEnv[i].IsAbnormal,
		})
	}
	for i := range img.ImageScanVuln.SensitiveFiles {
		res.SensitiveFile = append(res.SensitiveFile, img.ImageScanVuln.SensitiveFiles[i].Name)
	}

	for i := range img.ImageScanVuln.Vulns {
		vuln := apimodel.Vuln{
			Name:          img.ImageScanVuln.Vulns[i].Name,
			Severity:      img.ImageScanVuln.Vulns[i].Severity,
			Description:   img.ImageScanVuln.Vulns[i].Description,
			FixSuggestion: img.ImageScanVuln.Vulns[i].FixedBy,
			References:    img.ImageScanVuln.Vulns[i].Link,
			PkgName:       img.ImageScanVuln.Vulns[i].PkgName,
			PkgVersion:    img.ImageScanVuln.Vulns[i].PkgVersion,
		}

		if img.ImageScanVuln.Vulns[i].Metadata != nil {
			vuln.FixedVersion = img.ImageScanVuln.Vulns[i].Metadata.CNNVDs.FixSuggestion
			vuln.FixedVersion = img.ImageScanVuln.Vulns[i].Metadata.CNNVDs.FixSuggestion
			vuln.CVSS.Vector = img.ImageScanVuln.Vulns[i].Metadata.CVSS.CVSSv3Vector
		}
		if len(img.ImageScanVuln.Vulns[i].Metadata.CNVDs) > 0 {
			vuln.Title = img.ImageScanVuln.Vulns[i].Metadata.CNVDs[0].Title
		}
		score, _ := strconv.ParseFloat(img.ImageScanVuln.Vulns[i].Metadata.CVSS.CVSSv3Score, 64)

		vuln.CVSS.Score = score

		res.Vulns = append(res.Vulns, vuln)
	}

	response.JSONOK(ctx, response.WithItem(res))
}

// open api 镜像层级信息,返回全部数据，不分页
func (s *ImageOpenAPISvc) ListImgLayersByImageName(ctx *gin.Context) {
	registryName := ctx.Query("registryName")
	imageName := ctx.Query("imageName")

	if len(registryName) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no registy name:%s", registryName)))
		return
	}
	if len(imageName) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no image name:%s", registryName)))
		return
	}
	repoName, tag, err := ParseImageName(imageName)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	registries, _, err := s.RegistrySrv.SearchRegistry(ctx, component.SearchRegistryParam{
		Name:    registryName,
		UseType: model.UserRegistry,
	}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(registries) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond registry:%s", registryName)))
		return
	}

	image, _, err := s.ScannerSrv.SearchImages(ctx, component.SearchImageParam{
		FullRepoName: repoName,
		Tags:         tag,
		RegistryID:   registries[0].ID,
	}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(image) == 0 {
		response.JSONError(ctx, fmt.Errorf("not fond image:%s", imageName))
		return
	}

	images, err := s.ScannerSrv.ListImgLayers(ctx, image[0].ID, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := make([]apimodel.ImageLayerInfo, 0)
	for i := range images {
		res = append(res, apimodel.ImageLayerInfo{
			Digest:        images[i].ImageDigest,
			CreatedAt:     images[i].Created.Unix(),
			CreatedBy:     images[i].CreatedBy,
			Vulns:         util.DeDuplicationStringSlice(images[i].Vulus),
			Viruses:       images[i].Malicious,
			SensitiveFile: images[i].SensitiveFiles,
			WebshellInfo:  images[i].WebshellInfo,
			ImageID:       images[i].ImageID,
		})
	}
	response.JSONOK(ctx, response.WithItems(res))
}

func (s *ImageOpenAPISvc) CreateScanImageTask(ctx *gin.Context) {
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

	if body.ImageScanTaskInfo.StrategyName != "" {
		strategy, _, err := s.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{Name: body.ImageScanTaskInfo.StrategyName, All: consts.TrueString}, model.EmptyFilterForTotalQuery())
		if err != nil {
			response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
			return
		}
		if len(strategy) == 0 {
			response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not find scan strategy :%s", body.ImageScanTaskInfo.StrategyName)))
			return
		}
		taskInfo.StrategyID = strategy[0].ID
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

// 创建扫描任务(老接口，后期会废弃)
func (s *ImageOpenAPISvc) CreateScanTask(ctx *gin.Context) {
	type tem struct {
		Online        string `json:"online"`
		Keyword       string `json:"keyword"`
		FromType      string `json:"fromType"`
		SecurityIssue string `json:"securityIssue"`
		ImageType     string `json:"imageType"`
		Trusted       string `json:"trusted"`
		HasFixedVuln  string `json:"hasFixedVuln"`
		Reinforced    string `json:"reinforced"`
		StrategyName  string `json:"strategyName"`
		Operator      string `json:"operator"`
	}

	t := new(tem)
	if err := ctx.BindJSON(t); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusNotAcceptable, fmt.Errorf("所传参数不正确")))
		return
	}

	if t.FromType != model.ImageFromNode && t.FromType != model.ImageFromRegistry {
		response.JSONError(ctx, response.NewHttpError(http.StatusNotAcceptable, fmt.Errorf("fromType incorrect")))
		return
	}

	search := component.SearchImageWithScanParam{
		SearchWord:      t.Keyword,
		Kind:            t.SecurityIssue,
		Online:          t.Online,
		ImageType:       t.ImageType,
		Trusted:         t.Trusted,
		IsReinforce:     t.Reinforced,
		JustReturnImage: true,
	}
	// 只支持存在可修复漏洞的筛选
	if t.HasFixedVuln == consts.HasFixedvulnString {
		search.HasFixedVulu = consts.HasFixedvulnString
	}
	if t.FromType == model.ImageFromRegistry {
		search.FromType = model.UserRegistry
	} else if t.FromType == model.ImageFromNode {
		search.FromType = model.NodeBuffRegistry
	}

	scanInfo := task.UpdateTaskInfo{
		Scope:       consts.FullScan,
		TriggerType: consts.ManualTrigger,
		Operator:    t.Operator,
	}

	if t.StrategyName != "" {
		strategy, _, err := s.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{Name: t.StrategyName, All: consts.TrueString}, model.EmptyFilterForTotalQuery())
		if err != nil {
			response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
			return
		}
		scanInfo.StrategyID = strategy[0].ID
	}

	if err := s.ScannerSrv.ScanAllNow(ctx, scanInfo, search); err != nil {
		logging.Get().Err(err).Msg("crate scan task error")
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx)
}

// 仓库列表
func (s *ImageOpenAPISvc) SearchRegistry(ctx *gin.Context) {
	useType, _ := strconv.ParseInt(ctx.Query("usetype"), 10, 64)

	regType := ctx.Query("reg_type")
	filter := model.GetFilterWithDefaultValue(ctx)
	if useType <= 0 {
		useType = model.UserRegistry
	}
	param := component.SearchRegistryParam{UseType: useType}
	if regType != "" {
		param.RegType = strings.Split(strings.ReplaceAll(regType, " ", ""), ",")
	}

	registries, cnt, err := s.RegistrySrv.SearchRegistry(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := make([]Registry, len(registries))
	for i := range registries {
		registries[i].Deserialize()
		res[i] = ModelToRegistry(registries[i])
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ImageOpenAPISvc) CreateRegistry(ctx *gin.Context) {
	reg := Registry{}
	if err := ctx.BindJSON(&reg); err != nil {
		logging.Get().Err(err).Msg("CreateRegistry序列化数据出错")
		response.JSONError(ctx, err)
		return
	}
	modeReg := RegistryToModel(reg)

	modeReg.UseType = model.UserRegistry
	_, err := s.RegistrySrv.CreateRegistry(ctx, modeReg)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx)
}

func ParseImageName(imageName string) (string, string, error) {
	if !strings.Contains(imageName, ":") {
		return "", "", fmt.Errorf("illegal image name")
	}
	split := strings.Split(imageName, ":")
	if len(split) != 2 {
		return "", "", fmt.Errorf("illegal image name")
	}

	return split[0], split[1], nil
}

// Registry Registry表
type Registry struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`     // 仓库名字,仓库名是仓库的唯一标识,一个仓库名称  对应一个用户
	RegType      string `json:"regType"`  // 仓库类型
	Url          string `json:"url"`      // 如:docker.io/v2, quay.io/v2
	Username     string `json:"username"` // user for login registry
	Password     string `json:"password"` // DES加密
	Description  string `json:"description"`
	SyncInterval int64  `json:"syncInterval"` // 单位：分钟
	AccessKey    string `json:"accessKey"`    // 阿里云仓库的AccessKey
	AccessSecret string `json:"accessSecret"` // 阿里云仓库的AccessSecret
	InstanceID   string `json:"instanceId"`   // 阿里云仓库企业版实例ID
	RegionID     string `json:"regionId"`     // 阿里云仓库企业版地域ID
}

func ModelToRegistry(reg model.Registry) Registry {
	return Registry{
		ID:           reg.ID,
		Name:         reg.Name,
		RegType:      reg.RegType,
		Url:          reg.Url,
		Username:     reg.Username,
		Password:     reg.PasswordString,
		Description:  reg.Description,
		SyncInterval: reg.SyncInterval,
		AccessKey:    reg.AccessKey,
		AccessSecret: reg.AccessSecret,
		InstanceID:   reg.InstanceID,
		RegionID:     reg.RegionID,
	}
}

func RegistryToModel(reg Registry) model.Registry {
	return model.Registry{
		Name:           reg.Name,
		RegType:        reg.RegType,
		Url:            reg.Url,
		Username:       reg.Username,
		PasswordString: reg.Password,
		Description:    reg.Description,
		SyncInterval:   reg.SyncInterval,
		AccessKey:      reg.AccessKey,
		AccessSecret:   reg.AccessSecret,
		InstanceID:     reg.InstanceID,
		RegionID:       reg.RegionID,
	}
}

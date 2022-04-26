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
	ImageSrv      component.ScannerSrv
	RegistrySrv   component.RegistrySrvInterface
	ScanConfigSrv component.ScanConfigSrvInterface
}

func NewScannerOpenAPISrv(srv component.ScannerSrv,
	registrySrv component.RegistrySrvInterface, // nolint
	scanConfigSrv component.ScanConfigSrvInterface,
) *ImageOpenAPISvc {
	return &ImageOpenAPISvc{
		ImageSrv:      srv,
		RegistrySrv:   registrySrv,
		ScanConfigSrv: scanConfigSrv,
	}
}

// open-api镜像列表
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
	if fromTypeString == consts.ImageFromNode {
		param.FromType = model.ImageFromSafeNode
	} else if fromTypeString == consts.ImageFromRegistry {
		param.FromType = model.ImageFromTypeNormal
	}

	filter := model.GetFilterWithDefaultValue(ctx)
	filter.SortFiled = "full_repo_name"
	filter.SortBy = "asc"

	images, cnt, err := s.ImageSrv.SearchImageWithScan(ctx, param, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 数据规整
	for i := range images {
		if images[i].FromType == model.ImageFromSafeNode {
			split := strings.Split(images[i].FullRepoName, "/")
			// 节点镜像上传的tag:	NodeSafeTage="%s/" + NodeSafeSalt + "/%s/%s/%s/%s" // 仓库地址/tensorsec/hostname/ip/os/library/镜像名
			// tensorsecurity/tensorsec-safe-node-image-v2x54/10.65.72.54/linux/registry.t-appagile.com/google_containers/coredns
			if len(split) >= 6 {
				images[i].FullRepoName = strings.Join(split[5:], "/")
			}
		}
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
		if images[i].FromType == model.ImageFromSafeNode {
			im.FromType = consts.ImageFromNode
		} else if images[i].FromType == model.ImageFromTypeNormal {
			im.FromType = consts.ImageFromRegistry
		}

		res = append(res, im)
	}

	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// open-api镜像统计
func (s *ImageOpenAPISvc) ImageStatistic(ctx *gin.Context) {
	fromTypeString := ctx.Query("fromType")
	if fromTypeString == "" {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no fromType")))
		return
	}
	fromType := model.ImageFromTypeNormal

	if fromTypeString == consts.ImageFromNode {
		fromType = model.ImageFromSafeNode
	} else if fromTypeString == consts.ImageFromRegistry {
		fromType = model.ImageFromTypeNormal
	}

	view, err := s.ImageSrv.GetImageOverView(ctx, int64(fromType))
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
		UseType: model.RegistryUseTypeNormal,
	}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(registries) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond registry:%s", registryName)))
		return
	}

	image, _, err := s.ImageSrv.SearchImages(ctx, component.SearchImageParam{
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

	img, err := s.ImageSrv.GetImageDetail(ctx, image[0].ID)
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
	if img.FromType == model.ImageFromTypeNormal {
		res.FromType = consts.ImageFromRegistry
	} else if img.FromType == model.ImageFromSafeNode {
		res.FromType = consts.ImageFromRegistry
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

//  open api 镜像层级信息,返回全部数据，不分页
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
		UseType: model.RegistryUseTypeNormal,
	}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(registries) == 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond registry:%s", registryName)))
		return
	}

	image, _, err := s.ImageSrv.SearchImages(ctx, component.SearchImageParam{
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

	images, err := s.ImageSrv.ListImgLayers(ctx, image[0].ID, nil)
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

// 创建扫描任务
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

	if t.FromType != consts.ImageFromNode && t.FromType != consts.ImageFromRegistry {
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
	if t.HasFixedVuln == consts.HasFixedvulnStringd {
		search.HasFixedVulu = consts.HasFixedvulnStringd
	}
	if t.FromType == consts.ImageFromRegistry {
		search.FromType = model.ImageFromTypeNormal
	} else if t.FromType == consts.ImageFromNode {
		search.FromType = model.ImageFromSafeNode
	}

	scanInfo := task.UpdateTaskInfo{
		Scope:       consts.FullScan,
		TriggerType: consts.ManualTrigger,
		Operator:    t.Operator,
	}

	if t.StrategyName != "" {
		strategy, _, err := s.ScanConfigSrv.SearchStrategy(ctx, component.SearchStrategyParam{Name: t.StrategyName, All: consts.TrueString}, model.EmptyFilterForTheTotalQuery())
		if err != nil {
			response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
			return
		}
		scanInfo.StrategyID = strategy[0].ID
	}

	if err := s.ImageSrv.ScanAllNow(ctx, scanInfo, search); err != nil {
		logging.Get().Err(err).Msg("crate scan task error")
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

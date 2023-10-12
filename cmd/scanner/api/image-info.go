package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageInfoAPI struct {
	ImageSrv imagesecSrv.ImageService // Key:ImageFromType
}

func NewImageInfoAPI(
	imageSrv imagesecSrv.ImageService,
) *ImageInfoAPI {
	return &ImageInfoAPI{ImageSrv: imageSrv}
}

// 获取应用镜像的基础镜像列表
func (s *ImageInfoAPI) GetBaseImages(ctx *gin.Context) {
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	imageUniqueID := util.GetUint64FromQuery(ctx, "imageUniqueID")
	imageKeyword := util.GetKeywordFromQuery(ctx, "imageKeyword")

	filter := model.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:   imageFromType,
		ImageId:         imageID,
		ImageUniqueID:   imageUniqueID,
		DeployRecordID:  util.GetInt64FromQuery(ctx, "deployRecordID"),
		BaseImageEnable: true,

		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
			Keyword: imageKeyword,
		},
	})
	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(data.BaseImages),
		response.WithTotalItems(data.BaseImageCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

// 获取基础镜像的应用镜像列表
func (s *ImageInfoAPI) GetAppImages(ctx *gin.Context) {
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	imageUniqueID := util.GetUint64FromQuery(ctx, "imageUniqueID")
	imageKeyword := util.GetKeywordFromQuery(ctx, "imageKeyword")

	filter := model.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:  imageFromType,
		ImageId:        imageID,
		ImageUniqueID:  imageUniqueID,
		DeployRecordID: util.GetInt64FromQuery(ctx, "deployRecordID"),
		AppImageEnable: true,
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
			Keyword: imageKeyword,
		},
	})
	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(data.AppImages),
		response.WithTotalItems(data.AppImageCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ImageInfoAPI) GetLicense(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)
	param.LicenseSearch = util.GetStringSliceFromQuery(ctx, "name")
	filter := model.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:         param.ImageFromType,
		ImageId:               param.ImageID,
		ImageUniqueID:         param.ImageUniqueID,
		DeployRecordID:        param.DeployRecordID,
		DetectResultEnable:    true,
		DetectParam:           imagesecModel.DetectResultParam{SecurityPolicyIds: param.SecurityPolicyIds},
		LicenseEnable:         true,
		ScanResultSearchParam: param,
	})
	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(data.License),
		response.WithTotalItems(data.LicenseCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ImageInfoAPI) DeleteBaseImage(ctx *gin.Context) {
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	imageUniqueID := util.GetUint64FromQuery(ctx, "imageUniqueID")

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageId:       imageID,
		ImageUniqueID: imageUniqueID,
		ImageFromType: imageFromType,
	})

	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	flag := data.ImageBaseResponse.Flag
	flag = util.SetBit0(util.SetBit1(flag, imagesecModel.FlagAppImage), imagesecModel.FlagBaseImage)

	updater := map[string]interface{}{"flag": flag}
	param := imagesecModel.UpdateImageParam{
		ID:      data.ImageBaseResponse.ID,
		Updater: updater,
	}
	err = s.ImageSrv.UpdateImage(ctx, param)
	if err != nil {
		response.JSONError(ctx, scani18.DeleteBaseImage(err))
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: fmt.Sprintf("%s:%s", data.ImageBaseResponse.FullRepoName, data.ImageBaseResponse.Tag),
		ID:   strconv.Itoa(int(imageID)),
		Link: "api/v2/containerSec/scanner/images/baseImage",
	}))
}

func (s *ImageInfoAPI) CreateBaseImage(ctx *gin.Context) {
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	type ids struct {
		ImageIds []string `json:"imageIds"`
	}
	body := new(ids)
	if err := ctx.BindJSON(body); err != nil {
		response.JSONError(ctx, err)
		return
	}

	uni := make([]uint64, 0)
	for i := range body.ImageIds {
		if u, err := strconv.ParseUint(body.ImageIds[i], 10, 64); err == nil {
			uni = append(uni, u)
		}
	}
	if len(uni) == 0 {
		return
	}
	images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, imagesecModel.ImageSearchApiParam{
		UniqueIds:     uni,
		ImageFromType: imageFromType,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	names := make([]string, 0)

	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}

	for i := range images {
		flag := images[i].Flag
		flag = util.SetBit0(util.SetBit1(flag, imagesecModel.FlagBaseImage), imagesecModel.FlagAppImage)

		updater := map[string]interface{}{"flag": flag}
		param := imagesecModel.UpdateImageParam{
			ID:      images[i].ID,
			Updater: updater,
		}
		err = s.ImageSrv.UpdateImage(ctx, param)
		if err != nil {
			logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("UpdateImage")
			continue
		}
		names = append(names, fmt.Sprintf("%s/%s/%s", images[i].RegistryUrl, images[i].FullRepoName, images[i].Tag))
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: strings.Join(names, ","),
		Link: "api/v2/containerSec/scanner/images/baseImage",
	}))
}

func (s *ImageInfoAPI) SearchRelatedImage(ctx *gin.Context) {
	param := GetRelatedSearchParam(ctx)

	data, cnt, err := s.ImageSrv.SearchRelatedImage(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(data),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}

func (s *ImageInfoAPI) SearchImageWithScan(ctx *gin.Context) {
	body := imagesecModel.ImageSearchApiParam{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	if imageFromType != "" {
		body.ImageFromType = imageFromType
	}
	body.Filter = model.GetFilterWithDefaultValue(ctx)

	// trick 的做法：按 风险-安全-未知这个顺序排序
	body.Filter = body.Filter.SetSortFiled("flag").SetSortDesc()

	// 镜像列表需要这些数据
	assParam := imagesecModel.ImageAssociateParam{
		RegistryEnable:     true,
		VulnEnable:         true,
		NodeInfoEnable:     true,
		SubtaskEnable:      true,
		SimplePolicyEnable: true,
	}

	body.AssociateParam = assParam

	images, cnt, err := s.ImageSrv.ListImageWithScanInfo(ctx, body)
	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}
	for i := range images {
		images[i].Suggests = nil
		images[i].SecurityIssueView = nil
	}

	response.JSONOK(ctx, response.WithItems(images),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(body.Filter.Limit),
		response.WithStartIndex(body.Filter.Offset))
}

func (s *ImageInfoAPI) SearchAssetsImage(ctx *gin.Context) {

	type ImageResponse struct {
		Name  string `json:"name"`
		UUID  uint32 `json:"uuid"`
		Exit  bool   `json:"exit"`
		Image *imagesecModel.ImageBaseResponse
	}

	body := &imagesecModel.ImageSearchApiParam{}

	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	ans := make([]*ImageResponse, 0)
	if len(body.AssetImage) == 0 {
		response.JSONOK(ctx, response.WithItems(ans))
		return
	}

	uuid := make([]uint32, 0)
	for i := range body.AssetImage {
		uuid = append(uuid, body.AssetImage[i].UUID)
	}

	// 镜像列表需要这些数据
	assParam := imagesecModel.ImageAssociateParam{
		RegistryEnable:     true,
		VulnEnable:         true,
		NodeInfoEnable:     true,
		SubtaskEnable:      true,
		SimplePolicyEnable: true,
	}
	param := imagesecModel.ImageSearchApiParam{AssociateParam: assParam, UUIDs: uuid}

	images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, param)
	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}
	for i := range images {
		images[i].Suggests = nil
		images[i].SecurityIssueView = nil
	}

	uuidMap := make(map[uint32]*ImageResponse)

	for i := range body.AssetImage {
		im := body.AssetImage[i]

		uuidMap[im.UUID] = &ImageResponse{
			Name: im.Name,
			UUID: im.UUID,
			Exit: false,
		}
	}
	for i := range images {
		im := images[i]
		// 优先展示节点镜像
		if uuidMap[im.UUID].Exit && uuidMap[im.UUID].Image != nil &&
			uuidMap[im.UUID].Image.ImageFromType == imagesecModel.ImageFromNode {
			continue
		}

		uuidMap[im.UUID].Exit = true
		uuidMap[im.UUID].Image = im
	}

	for i := range uuidMap {
		ans = append(ans, uuidMap[i])
	}
	response.JSONOK(ctx, response.WithItems(ans))
}

func (s *ImageInfoAPI) GetRegistryProject(ctx *gin.Context) {
	regID := util.GetInt64FromQuery(ctx, "regID")
	nodeID := util.GetInt64FromQuery(ctx, "nodeID")
	projectKeyword := util.GetKeywordFromQuery(ctx, "projectKeyword")
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	repos, err := s.ImageSrv.SearchProject(ctx, imagesecModel.SearchProjectParam{
		RegID:         regID,
		ImageFromType: imageFromType,
		NodeID:        nodeID,
		Keyword:       projectKeyword,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(repos),
		response.WithTotalItems(int64(len(repos))))
}

func (s *ImageInfoAPI) SearchImages(ctx *gin.Context) {
	imageKeyword := util.GetKeywordFromQuery(ctx, "search")
	uuids := util.GetUint32SliceFromQuery(ctx, "uuids")

	filter := model.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit)
	param := imagesecModel.ImageSearchApiParam{
		ImageKeyword: imageKeyword,
		UUIDs:        uuids,
		Filter:       filter,
	}
	res := make([]imagesecModel.ImageBaseResponse, 0)

	if imageKeyword == "" || len(param.UUIDs) == 0 {
		response.JSONOK(ctx, response.WithItems(res),
			response.WithTotalItems(0),
			response.WithItemsPerPage(filter.Limit),
			response.WithStartIndex(filter.Offset))
	}

	images, cnt, err := s.ImageSrv.ListImageWithScanInfo(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(images),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ImageInfoAPI) VerifyExistence(ctx *gin.Context) {

	imageKeyword := util.GetKeywordFromQuery(ctx, "search")
	uuids := util.GetUint32SliceFromQuery(ctx, "uuids")

	filter := model.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit)
	param := imagesecModel.ImageSearchApiParam{
		ImageKeyword: imageKeyword,
		UUIDs:        uuids,
		Filter:       filter,
	}
	res := make(map[uint32]bool)
	for i := range uuids {
		res[uuids[i]] = false
	}

	type exit struct {
		VerifyExistence map[uint32]bool `json:"verifyExistence"`
	}

	if imageKeyword == "" || len(param.UUIDs) == 0 {
		response.JSONOK(ctx, response.WithItem(exit{VerifyExistence: res}))
		return
	}

	images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	for i := range images {
		res[images[i].UUID] = true
	}

	response.JSONOK(ctx, response.WithItem(exit{VerifyExistence: res}))
}

func (s *ImageInfoAPI) ExistenceCount(ctx *gin.Context) {

	imageKeyword := util.GetKeywordFromQuery(ctx, "search")
	uuids := util.GetUint32SliceFromQuery(ctx, "uuids")
	type exits struct {
		Exit int `json:"exit"`
		All  int `json:"all"`
	}

	filter := model.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit)
	param := imagesecModel.ImageSearchApiParam{
		ImageFromType: imagesecModel.ImageFromNode,
		ImageKeyword:  imageKeyword,
		UUIDs:         uuids,
		Filter:        filter,
	}
	if imageKeyword == "" || len(param.UUIDs) == 0 {
		response.JSONOK(ctx, response.WithItem(exits{Exit: 0, All: 0}))
		return
	}

	images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	res := make(map[uint32]bool)
	for i := range param.UUIDs {
		res[param.UUIDs[i]] = false
	}
	for i := range images {
		res[images[i].UUID] = true
	}
	exit, all := 0, 0

	for _, v := range res {
		if v {
			exit++
		}
		all++
	}
	response.JSONOK(ctx, response.WithItem(exits{Exit: exit, All: all}))
}

// 内部使用
func (s *ImageInfoAPI) RiskImageOverview(ctx *gin.Context) {
	type ImageRiskOverview struct {
		Uuid               uint32 `json:"uuid"`
		IsTrusted          bool   `json:"isTrusted"`
		IsSecure           bool   `json:"isSecure"`
		VulnerabilityNum   int32  `json:"vulnerabilityNum"`
		VulnerabilityLevel string `json:"vulnerabilityLevel"`
		MalwareNum         int32  `json:"malwareNum"`
		SensitiveFilesNum  int32  `json:"sensitiveFilesNum"`
		WebshellNum        int32  `json:"webshellNum"`
	}

	type Body struct {
		UUIDS []uint32 `json:"uuids"`
	}
	body := new(Body)
	if err := ctx.BindJSON(body); err != nil {
		response.JSONError(ctx, fmt.Errorf("not get image uuid"))
		return
	}
	empty := make([]ImageRiskOverview, 0)
	if len(body.UUIDS) == 0 {
		response.JSONOK(ctx, response.WithItems(empty))
		return
	}
	images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, imagesecModel.ImageSearchApiParam{UUIDs: body.UUIDS})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	over := make(map[uint32]ImageRiskOverview)

	for i := range images {
		data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
			ImageId:         images[i].ID,
			VulnEnable:      true,
			MalwareEnable:   true,
			SensitiveEnable: true,
			WebshellEnable:  true,
		})
		if err != nil {
			response.JSONError(ctx, err)
			return
		}

		over[data.Image.ImageUUID] = ImageRiskOverview{
			Uuid:               data.Image.ImageUUID,
			VulnerabilityNum:   int32(len(data.Vuln)),
			VulnerabilityLevel: model.GetSeverity(data.GetMaxVulnLevel()),
			MalwareNum:         int32(data.MalwareCnt),
			SensitiveFilesNum:  int32(data.SensitiveCnt),
			WebshellNum:        int32(data.WebshellCnt),
			IsTrusted:          util.ExistBit1(data.Image.Flag, imagesecModel.FlagImageTrusted), // 可信镜像查询
			IsSecure:           data.GetRiskScore() <= consts.SecureImageRiskScore,
		}
	}

	ans := make([]ImageRiskOverview, 0)
	for _, k := range over {
		ans = append(ans, k)
	}

	response.JSONOK(ctx, response.WithTotalItems(int64(len(ans))), response.WithItems(ans))
}

func (s *ImageInfoAPI) ImageOverview(ctx *gin.Context) {
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	overView, err := s.ImageSrv.GetImageOverView(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	switch imageFromType {
	case imagesecModel.ImageFromNode:
		response.JSONOK(ctx, response.WithItem(overView.NodeImageOverView))

	case imagesecModel.ImageFromRegistry:
		response.JSONOK(ctx, response.WithItem(overView.RegImageOverView))
	}
	return
}

func (s *ImageInfoAPI) TopRiskImage(ctx *gin.Context) {
	overView, err := s.ImageSrv.TopRiskImage(ctx)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(overView))
}

func (s *ImageInfoAPI) SearchResources(ctx *gin.Context) {
	keyword := util.GetKeywordFromQuery(ctx, "keyword")
	imageUUID := util.GetUint32FromQuery(ctx, "imageUUID")
	webshellMD5 := util.GetKeywordFromQuery(ctx, "webshellMD5")
	malwareMD5 := util.GetKeywordFromQuery(ctx, "malwareMD5")
	sensitiveMD5 := util.GetKeywordFromQuery(ctx, "sensitiveMD5")
	vulnUniqueID := util.GetUint64FromQuery(ctx, "vulnUniqueID")
	pkgUniqueID := util.GetUint64FromQuery(ctx, "pkgUniqueID")
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	imageUniqueID := util.GetUint64FromQuery(ctx, "imageUniqueID")
	param := imagesecModel.SearchResourceParam{
		ImageID:       imageID,
		ImageUniqueID: imageUniqueID,
		Keyword:       keyword,
		ImageUUID:     imageUUID,
		VulnUniqueID:  vulnUniqueID,
		PkgUniqueID:   pkgUniqueID,
		WebshellMD5:   webshellMD5,
		MalwareMD5:    malwareMD5,
		SensitiveMD5:  sensitiveMD5,
		Filter:        model.GetFilter(ctx).SetMaxLimit(consts.DefaultMaxLimit),
	}

	ans, cnt, err := s.ImageSrv.SearchResources(ctx, param)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(param.Filter.Limit),
		response.WithStartIndex(param.Filter.Offset))
}

func (s *ImageInfoAPI) GetImageByVuln(ctx *gin.Context) {

	// 资产那边使用，暂时保留
	type VulnImageList struct {
		FullRepoName string `json:"full_repo_name"`
		Library      string `json:"library"`
		Tags         string `json:"tags"`
		Digest       string `json:"digest"`
		ImageId      int64  `json:"id"`
	}

	vulnName := ctx.Query("vulnName")
	pkgName := ctx.Query("pkgName")
	pkgVersion := ctx.Query("pkgVersion")

	if vulnName == "" || pkgName == "" || pkgVersion == "" {
		response.JSONError(ctx, fmt.Errorf("vulnName,pkgName,pkgVersion must not empty"))
		return
	}
	vulnUniqueID := util.GenerateUUID64(fmt.Sprintf(consts.UniqueVulnFamat, vulnName, pkgName, pkgVersion))
	logging.Get().Info().Str("vuln", fmt.Sprintf("%s-%s-%s", vulnName, pkgName, pkgVersion)).Uint64("vulnUniqueID", vulnUniqueID)
	filter := model.EmptyFilter().SetDefault().SetLimit(consts.DefaultMaxLimit)
	res, cnt, err := s.ImageSrv.ListImageWithScanInfo(ctx, imagesecModel.ImageSearchApiParam{
		VulnUniqueID: vulnUniqueID,
		Filter:       filter,
	})
	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}
	ans := make([]VulnImageList, 0)
	for i := range res {
		ans = append(ans, VulnImageList{
			FullRepoName: res[i].FullRepoName,
			Library:      res[i].RegistryUrl,
			Tags:         res[i].Tag,
			Digest:       res[i].Tag,
			ImageId:      res[i].ID,
		})
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))

}

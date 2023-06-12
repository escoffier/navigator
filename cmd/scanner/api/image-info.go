package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-i18"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageInfoAPI struct {
	ImageSrv map[string]imagesecSrv.ImageService // Key:ImageFromType
}

func NewImageInfoAPI(
	imageSrv map[string]imagesecSrv.ImageService,
) *ImageInfoAPI {
	return &ImageInfoAPI{ImageSrv: imageSrv}
}

// 获取应用镜像的基础镜像列表
func (s *ImageInfoAPI) ListBaseToAppImage(ctx *gin.Context) {

	imageID := util.GetInt64FromQuery(ctx, "imageID")
	keyword := util.GetKeywordFromQuery(ctx, "keyword")
	filter := model.GetFilter(ctx)

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:   imagesecModel.ImageFromRegistry,
		ImageId:         imageID,
		BaseImageEnable: true,
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
			ImageID: imageID,
			Keyword: keyword,
		},
		Filter: filter,
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
func (s *ImageInfoAPI) ListAppToBaseImage(ctx *gin.Context) {
	imageID := util.GetInt64FromQuery(ctx, "imageID")
	keyword := util.GetKeywordFromQuery(ctx, "keyword")
	filter := model.GetFilter(ctx)

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageFromType:  imagesecModel.ImageFromRegistry,
		ImageId:        imageID,
		AppImageEnable: true,
		ScanResultSearchParam: imagesecModel.ScanResultSearchParam{
			ImageID: imageID,
			Keyword: keyword,
		},
		Filter: filter,
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

func (s *ImageInfoAPI) ListBaseImage(ctx *gin.Context) {
	filter := model.GetFilter(ctx)
	// 排序对性能影响很大
	// filter.SortFiled = "full_repo_name"
	// filter.SortBy = "asc"
	keyword := ctx.Query("search")
	images, cnt, err := s.getImageSrv(ctx).ListImageWithScanInfo(ctx,
		imagesecModel.ImageListParam{
			ImageFromType: imagesecModel.ImageFromRegistry, // 只有仓库镜像有这个功能
			ImageKeyword:  keyword,
			ImageAttr:     imagesecModel.ImageAttrParam{ImageType: model.BaseImageTypeString},
			Filter:        filter,
		})
	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(images),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset),
	)
}

func (s *ImageInfoAPI) DeleteBaseImage(ctx *gin.Context) {

	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil || imageID <= 0 {
		response.JSONError(ctx, scani18.NotGetImageID())
		return
	}

	data, err := s.getImageSrv(ctx).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{ImageId: imageID, ImageFromType: imagesecModel.ImageFromRegistry})

	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}
	updater := map[string]interface{}{"flag": util.SetBit0(data.ImageBaseResponse.Flag, model.FlagBaseImage)}
	param := imagesecModel.UpdateImageParam{
		ID:      imageID,
		Updater: updater,
	}
	err = s.getImageSrv(ctx).UpdateImage(ctx, param)
	if err != nil {
		response.JSONError(ctx, scani18.DeleteBaseImage(err))
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: fmt.Sprintf("%s:%s", data.ImageBaseResponse.FullRepoName, data.ImageBaseResponse.Tag),
		ID:   strconv.Itoa(int(imageID)),
		Link: "api/v2/containerSec/scanner/images/base/" + strconv.Itoa(int(imageID)),
	}))
}

func (s *ImageInfoAPI) CreateBaseImage(ctx *gin.Context) {
	type ids struct {
		ImageIds []int64 `json:"image_ids"`
	}
	body := new(ids)
	if err := ctx.BindJSON(body); err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(body.ImageIds) == 0 {
		return
	}
	images, _, err := s.getImageSrv(ctx).ListImageWithScanInfo(ctx, imagesecModel.ImageListParam{ImageIds: body.ImageIds,
		ImageFromType: imagesecModel.ImageFromRegistry})
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
		updater := map[string]interface{}{"flag": util.SetBit1(images[i].Flag, model.FlagBaseImage)}
		param := imagesecModel.UpdateImageParam{
			ID:      images[i].ID,
			Updater: updater,
		}
		err = s.getImageSrv(ctx).UpdateImage(ctx, param)
		if err != nil {
			logging.Get().Err(err).Int64("imageID", images[i].ID).Msg("UpdateImage")
			continue
		}
		names = append(names, fmt.Sprintf("%s/%s/%s", images[i].RegistryUrl, images[i].FullRepoName, images[i].Tag))
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: strings.Join(names, ","),
		Link: "api/v2/containerSec/scanner/images/bases",
	}))
}

func (s *ImageInfoAPI) SearchImageWithScan(ctx *gin.Context) {
	body := imagesecModel.ImageListParam{}
	if err := ctx.BindJSON(&body); err != nil {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, err))
		return
	}
	body.ImageFromType = util.GetKeywordFromQuery(ctx, "imageFromType")

	body.Filter = model.GetFilterWithDefaultValue(ctx)

	images, cnt, err := s.getImageSrv(ctx).ListImageWithScanInfo(ctx, body)
	if err != nil {
		response.JSONError(ctx, scani18.SearchImage(err))
		return
	}
	for i := range images {
		images[i].Suggests = nil
		images[i].RiskPolicy = nil
		images[i].TotalPolicy = nil
	}

	response.JSONOK(ctx, response.WithItems(images),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(body.Filter.Limit),
		response.WithStartIndex(body.Filter.Offset))
}

func (s *ImageInfoAPI) GetRegistryProject(ctx *gin.Context) {
	regID, _ := strconv.ParseInt(ctx.Query("regID"), 10, 64)
	nodeID, _ := strconv.ParseInt(ctx.Query("nodeID"), 10, 64)
	projectKeyword := ctx.Query("projectKeyword")

	repos, err := s.getImageSrv(ctx).SearchProject(ctx, imagesecModel.SearchProjectParam{
		RegID:   regID,
		NodeID:  nodeID,
		Keyword: projectKeyword,
	})
	if err != nil {
		response.JSONError(ctx, i18.SearchErr(err))
		return
	}

	response.JSONOK(ctx, response.WithItems(repos),
		response.WithTotalItems(int64(len(repos))))
}

func (s *ImageInfoAPI) getImageSrv(ctx *gin.Context) imagesecSrv.ImageService {
	imageFromType := util.GetKeywordFromQuery(ctx, "imageFromType")
	if imageFromType == "" {
		imageFromType = imagesecModel.ImageFromRegistry
	}
	if err := imagesecModel.ImageFromType(imageFromType).Check(); err != nil {
		logging.Get().Error().Msg("not get imageFromType")
		imageFromType = imagesecModel.ImageFromRegistry
	}

	return s.ImageSrv[imageFromType]
}

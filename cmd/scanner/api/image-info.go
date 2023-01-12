package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageInfoAPI struct {
	ImageSrv component.ImageSrvInterface
}

func NewImageInfoAPI(
	imageSrv component.ImageSrvInterface,
) *ImageInfoAPI {
	return &ImageInfoAPI{ImageSrv: imageSrv}
}

func (s *ImageInfoAPI) ListBaseToAppImage(ctx *gin.Context) {

	imageID := util.GetInt64FromQuery(ctx, "imageID")
	if imageID <= 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not get imageID")))
		return
	}

	keyword := util.GetKeywordFromQuery(ctx, "keyword")
	filter := model.GetFilter(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:         imageID,
		BaseImageEnable: true,
		ScanResultSearchParam: model.ScanResultSearchParam{
			ImageID: imageID,
			Keyword: keyword,
		},
		Filter: filter,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(data.BaseImages),
		response.WithTotalItems(data.BaseImageCnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

func (s *ImageInfoAPI) ListAppToBaseImage(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	keyword := ctx.Query("keyword")
	filter := model.GetFilter(ctx)

	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:        imageID,
		AppImageEnable: true,
		ScanResultSearchParam: model.ScanResultSearchParam{
			ImageID: imageID,
			Keyword: keyword,
		},
		Filter: filter,
	})
	if err != nil {
		response.JSONError(ctx, err)
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
	images, cnt, err := s.ImageSrv.ListImageWithScanInfo(ctx,
		model.ImageListParam{
			Keyword:   keyword,
			ImageAttr: model.ImageAttrParam{ImageType: model.BaseImageTypeString},
		}, filter)
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

func (s *ImageInfoAPI) DeleteBaseImage(ctx *gin.Context) {
	imageID, err := strconv.ParseInt(ctx.Param("imageID"), 10, 64)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{ImageId: imageID})

	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	updater := map[string]interface{}{"flag": util.SetBit0(data.ImageBaseResponse.Flag, model.FlagBaseImage)}

	err = s.ImageSrv.UpdateImage(ctx, fmt.Sprintf("id = %d", imageID), updater)
	if err != nil {
		response.JSONError(ctx, err)
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
	images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, model.ImageListParam{ImageIds: body.ImageIds}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	names := make([]string, 0)
	for i := range images {
		updater := map[string]interface{}{"flag": util.SetBit1(images[i].Flag, model.FlagBaseImage)}
		err = s.ImageSrv.UpdateImage(ctx, fmt.Sprintf("id = %d", images[i].ID), updater)
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

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

const (
	digestLength         = 71
	repositoryNameLength = 64
)

type Scanner struct {
	Srv component.ScannerSrv
	log *logging.Logger
}

func (s *Scanner) GetSimpleImageDetail(ctx *gin.Context) {
	tag := ctx.Query("tag")
	digest := ctx.Query("digest")
	library := ctx.Query("library")
	fullRepoName := ctx.Query("full_repo_name")
	res := s.Srv.GetSimpleImageDetail(ctx, tag, digest, library, fullRepoName)
	response.JSONOK(ctx, response.WithItem(res))
}

func (s *Scanner) ListVulnRelation(ctx *gin.Context) {
	tmp := []model.VulnImageList{}
	str := ctx.Query("imageinfo")
	str, _ = url.QueryUnescape(str)
	fmt.Println("解码串为:", str)
	json.Unmarshal([]byte(str), &tmp)
	res, _ := s.Srv.GetRelationImage(ctx, tmp)
	response.JSONOK(ctx, response.WithItems(res))
}

func (s *Scanner) ScannedByVulnDetails(ctx *gin.Context) {
	name := ctx.Param("name")
	res, err := s.Srv.GetVulnDetails(ctx, name)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(res))
}

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

func (s *Scanner) ListScannedByVulnOverview(ctx *gin.Context) {
	res, _ := s.Srv.GetVulnOverView(ctx)
	response.JSONOK(ctx, response.WithItem(res), response.WithExportFileStatus(0))
}

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

func (s *Scanner) ScanAllNow(ctx *gin.Context) {
	registerUrl := ctx.Query("fromUrl")
	// asynchronous execution, no matter what return no error
	go s.Srv.ScanAllNow(ctx, registerUrl)
	response.JSONOK(ctx)
}

func (s *Scanner) StartScanOne(ctx *gin.Context) {
	type resp struct {
		Status string `json:"status"`
	}
	type tmpRecv struct {
		ImgId int64 `json:"id"`
	}
	tmp := tmpRecv{}
	// json := make(map[string]interface{})
	ctx.BindJSON(&tmp)
	// fmt.Println("收获JSON为:", json)
	err := s.Srv.TickScanOne(ctx, tmp.ImgId, "")
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(resp{Status: "OK"}))
}

func (s *Scanner) GetScanOneStatus(ctx *gin.Context) {
	type respT struct {
		EndTime    time.Time `json:"end_time"`
		ScanStatus string    `json:"scan_status"`
	}
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

func (s *Scanner) ListScannedByImageOverview(ctx *gin.Context) {
	registerUrl := ctx.Query("fromUrl")

	view, err := s.Srv.GetImageOverView(ctx, registerUrl)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*view))
}

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

func (s *Scanner) ListScannedByImageList(ctx *gin.Context) {
	search := ctx.Query("search")
	if len(search) > 64 {
		response.JSONError(ctx, errors.New("the maximum value is exceeded"))
		return
	}
	kind := ctx.Query("kind")
	sortBy := ctx.Query("sortOrder")
	offset, _ := strconv.ParseInt(ctx.Query("offset"), 10, 64)
	limit, _ := strconv.ParseInt(ctx.Query("limit"), 10, 64)
	online, _ := strconv.ParseBool(ctx.Query("online"))
	logging.GetLogger().Info().Msg(fmt.Sprintf("get kind:%s", kind))
	images, cnt, err := s.Srv.SearchImages(ctx, search, kind, online, &model.Filter{
		PageSize: limit,
		SortBy:   sortBy,
		Offset:   offset,
	})
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	// 数据规整
	res := make([]model.ImageResponse, 0)
	for i := range images {
		im := model.ImageResponse{
			ID:           images[i].ID,
			Digest:       images[i].Digest,
			Library:      images[i].Library,
			ScanStatus:   images[i].ScanStatus,
			CompleteTime: images[i].CompleteTime,
			Questions:    images[i].Questions,
			FullRepoName: images[i].FullRepoName,
			Tags:         images[i].Tags,
		}
		res = append(res, im)
	}
	response.JSONOK(ctx, response.WithItems(res),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(limit),
		response.WithStartIndex(offset))
}

// ListImgLayers 镜像的回溯信息
func (s *Scanner) ListImgLayers(ctx *gin.Context) {
	imgDigest := ctx.Param("imgDigest")

	images, err := s.Srv.ListImgLayers(ctx, imgDigest, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItems(images))
}

func (s *Scanner) ImgLayerInfo(ctx *gin.Context) {
	layerDigest := ctx.Param("layerDigest")

	image, err := s.Srv.ImgLayerInfo(ctx, layerDigest, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	response.JSONOK(ctx, response.WithItem(*image))
}

func NewScannerSrv(srv component.ScannerSrv) *Scanner {
	return &Scanner{
		Srv: srv,
		log: logging.GetLogger(),
	}
}

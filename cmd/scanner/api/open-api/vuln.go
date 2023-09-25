package openapi

// import (
// 	"errors"
// 	"fmt"
// 	"net/http"
// 	"strconv"
//
// 	"github.com/gin-gonic/gin"
//
// 	apimodel "gitlab.com/piccolo_su/vegeta/cmd/scanner/api/model"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
// 	"gitlab.com/piccolo_su/vegeta/pkg/model"
// 	"gitlab.com/piccolo_su/vegeta/pkg/response"
// 	"gitlab.com/piccolo_su/vegeta/pkg/util"
// )
//
// type VulnServer struct {
// 	vulnService component.VulnServiceInterface
// 	imageSrv    component.ScannerSrv
// }
//
// func NewVulnServer(vulnService component.VulnServiceInterface, imageSrv component.ScannerSrv) *VulnServer {
// 	return &VulnServer{
// 		vulnService: vulnService,
// 		imageSrv:    imageSrv,
// 	}
// }
//
// func (v *VulnServer) List(ctx *gin.Context) {
// 	// 获取特定镜像的漏洞
// 	registryName := ctx.Query("registryName")
// 	imageName := ctx.Query("imageName")
//
// 	imageIds := make([]int64, 0)
// 	if registryName != "" && imageName != "" {
// 		repoName, tag, err := ParseImageName(imageName)
// 		if err != nil {
// 			response.JSONError(ctx, err)
// 			return
// 		}
//
// 		images, _, err := v.imageSrv.SearchImages(ctx, component.SearchImageParam{
// 			FullRepoName: repoName,
// 			Tags:         tag,
// 		}, nil)
// 		if err != nil {
// 			response.JSONError(ctx, err)
// 			return
// 		}
// 		for i := range images {
// 			if images[i].Registry != nil && images[i].Registry.Name == registryName {
// 				imageIds = append(imageIds, images[i].ID)
// 			}
// 		}
// 		if len(imageIds) == 0 {
// 			response.JSONError(ctx, fmt.Errorf("not fond image:(%s)%s", registryName, imageName))
// 			return
// 		}
// 	} else {
// 		// 默认查在线的
// 		onlineIds, err := v.imageSrv.GetOnlineImageId(ctx)
// 		if err != nil {
// 			response.JSONError(ctx, err)
// 			return
// 		}
// 		if len(onlineIds) == 0 {
// 			response.JSONOK(ctx, response.WithItems([]model.Vuln{}))
// 			return
// 		}
// 	}
//
// 	search := ctx.Query("keyword")
// 	if len(search) > 64 {
// 		response.JSONError(ctx, errors.New("the maximum value is exceeded"))
// 		return
// 	}
// 	filter := model.GetFilterWithDefaultValue(ctx)
// 	if filter.SortFiled == "" {
// 		filter.SortFiled = "severity_int"
// 	}
// 	if filter.SortBy == "" {
// 		filter.SortBy = consts.SortByDesc
// 	}
//
// 	vulns, cnt, err := v.vulnService.SearchVulns(ctx, model.SearchVulnParam{VulnKeyword: search, ImageIds: imageIds}, filter)
// 	if err != nil {
// 		response.JSONError(ctx, err)
// 		return
// 	}
//
// 	res := make([]apimodel.Detail, len(vulns))
// 	for i := range vulns {
// 		res[i] = apimodel.ModelToOpenapiDetail(vulns[i])
// 	}
//
// 	response.JSONOK(ctx, response.WithItems(res),
// 		response.WithTotalItems(cnt),
// 		response.WithItemsPerPage(filter.Limit),
// 		response.WithStartIndex(filter.Offset))
// }
//
// func (v *VulnServer) Detail(ctx *gin.Context) {
// 	vulnName := ctx.Query("vulnName")
// 	pkgName := ctx.Query("pkgName")
// 	pkgVersion := ctx.Query("pkgVersion")
//
// 	if vulnName == "" || pkgName == "" || pkgVersion == "" {
// 		response.JSONError(ctx, fmt.Errorf("vulnName,pkgName,pkgVersion must not empty"))
// 		return
// 	}
// 	uniqueVuln := util.GenerateUUID64(fmt.Sprintf(consts.UniqueVulnFamat, vulnName, pkgName, pkgVersion))
//
// 	res, _, err := v.vulnService.SearchVulns(ctx, model.SearchVulnParam{UniqueVulns: []uint64{uniqueVuln}}, nil)
//
// 	if err != nil {
// 		response.JSONError(ctx, err)
// 		return
// 	}
// 	if len(res) == 0 {
// 		response.JSONError(ctx, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("not fond the vuln")))
// 		return
// 	}
// 	response.JSONOK(ctx, response.WithItem(apimodel.ModelToOpenapiDetail(res[0])))
// }
//
// func (v *VulnServer) GetVulnTopNImage(ctx *gin.Context) {
//
// 	topN, err := strconv.ParseInt(ctx.Query("topn"), 10, 64)
// 	if err != nil || topN <= 0 {
// 		topN = consts.DefaultVulnTopNImage
// 	}
// 	if topN > consts.MaxVulnTopNImage {
// 		topN = consts.MaxVulnTopNImage
// 	}
// 	type TopN struct {
// 		Image   string  `json:"image"`
// 		Score   float64 `json:"score"`
// 		ImageID int64   `json:"imageID"`
// 	}
//
// 	res, err := v.imageSrv.GetOnlineVulnTopN(ctx, topN)
// 	if err != nil {
// 		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
// 		return
// 	}
// 	ans := make([]TopN, len(res))
// 	for i := range res {
// 		ans[i] = TopN{
// 			Image:   fmt.Sprintf("%s/%s:%s", res[i].Library, res[i].Name, res[i].Tag),
// 			Score:   res[i].Score,
// 			ImageID: res[i].ImageID,
// 		}
// 	}
//
// 	response.JSONOK(ctx, response.WithItems(ans), response.WithTotalItems(int64(len(res))))
// }
//
// func (v *VulnServer) Statistic(ctx *gin.Context) {
// 	type Statistic struct {
// 		VulnTotal int64               `json:"vulnTotal"`
// 		Severity  model.SeverityCount `json:"severity"`
// 	}
//
// 	res, err := v.imageSrv.GetOnlineVulnOverView(ctx)
// 	if err != nil {
// 		response.JSONError(ctx, response.NewHttpError(http.StatusInternalServerError, err))
// 		return
// 	}
// 	ans := Statistic{
// 		VulnTotal: res.VulnTotal,
// 		Severity:  res.Severity,
// 	}
// 	response.JSONOK(ctx, response.WithItem(ans), response.WithExportFileStatus(0))
// }

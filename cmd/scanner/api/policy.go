package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-i18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type DetectAPI struct {
	policySrv imagesecSrv.SecurityPolicyService
}

func NewDetectAPI(
	policySrv imagesecSrv.SecurityPolicyService,
) *DetectAPI {
	return &DetectAPI{policySrv: policySrv}
}

func (api *DetectAPI) CreatePolicy(ctx *gin.Context) {
	data := imagesecModel.SecurityPolicy{}
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, i18.CreateErr(err))
		return
	}
	data.IsDefault = false
	if err := api.policySrv.CreatePolicy(ctx, &data); err != nil {
		response.JSONError(ctx, i18.CreateErr(err))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(data.ID)), Name: data.Name}))
}

func (api *DetectAPI) UpdatePolicy(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	if id <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get policy ID"))
		return
	}
	data := imagesecModel.SecurityPolicy{}
	if err := ctx.BindJSON(&data); err != nil {
		response.JSONError(ctx, scani18.ParameterErr(nil))
		return
	}

	policy, _, errI18 := api.policySrv.SearchPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Ids: []int64{id}})

	if errI18 != nil {
		response.JSONError(ctx, errI18)
		return
	}
	if len(policy) == 0 {
		response.JSONError(ctx, scani18.GetPolicy(nil))
		return
	}

	if err := api.policySrv.UpdatePolicy(ctx, id, &data); err != nil {
		response.JSONError(ctx, scani18.UpdatePolicy(err))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(policy[0].ID)), Name: policy[0].Name}))
}

func (api *DetectAPI) DeletePolicy(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	if id <= 0 {
		response.JSONError(ctx, scani18.NotGetPolicyID())
		return
	}

	policy, _, errI18 := api.policySrv.SearchPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{Ids: []int64{id}})

	if errI18 != nil {
		response.JSONError(ctx, errI18)
		return
	}
	if len(policy) == 0 {
		response.JSONError(ctx, scani18.GetPolicy(nil))
		return
	}

	if err := api.policySrv.DeletePolicy(ctx, id); err != nil {
		response.JSONError(ctx, scani18.DeletePolicy(err))
		return
	}
	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{ID: strconv.Itoa(int(policy[0].ID)), Name: policy[0].Name}))
}

func (api *DetectAPI) GetPolicyDetail(ctx *gin.Context) {
	id := util.GetInt64FromQuery(ctx, "id")
	if id <= 0 {
		response.JSONError(ctx, fmt.Errorf("not get policy ID"))
		return
	}

	polices, _, err := api.policySrv.SearchPolicy(ctx, imagesecModel.SearchSecurityPolicyParam{
		Ids:      []int64{id},
		NotCount: true,
		Deleted:  consts.FalseString,
	})
	if err != nil {
		response.JSONError(ctx, scani18.GetPolicy(err))
		return
	}
	if len(polices) == 0 {
		response.JSONError(ctx, scani18.GetPolicy(err))
		return
	}

	if polices[0].Scope.AllCluster {
		polices[0].Scope.ClusterKey = make([]string, 0)
	}
	response.JSONOK(ctx, response.WithItem(polices[0]))
}

func (api *DetectAPI) SearchPolicy(ctx *gin.Context) {
	param := GetScanResultSearchParamFromCtx(ctx)
	filter := model.GetFilter(ctx)
	param2 := imagesecModel.SearchSecurityPolicyParam{
		Filter:  model.GetFilter(ctx).SetSortDesc().SetSortFiled("updated_at").SetLimit(0).SetOffset(0),
		Keyword: param.Keyword,
		Deleted: consts.FalseString,
	}

	polices, cnt, err := api.policySrv.SearchPolicy(ctx, param2)
	if err != nil {
		response.JSONError(ctx, scani18.SearchPolicy(err))
		return
	}
	var defaultP *imagesecModel.SecurityPolicy
	for i := range polices {
		if polices[i].IsDefault {
			defaultP = polices[i]
			break
		}
	}
	ans := make([]*imagesecModel.SecurityPolicy, 0)
	if defaultP != nil {
		ans = append(ans, defaultP)
	}
	for i := range polices {
		if polices[i].Scope.AllCluster {
			polices[i].Scope.ClusterKey = make([]string, 0)
		}

		if polices[i].IsDefault {
			continue
		}
		ans = append(ans, polices[i])
	}

	// 程序中分页
	start := int(filter.Offset)
	end := int(filter.Offset + filter.Limit)

	if len(ans) <= start {
		ans = make([]*imagesecModel.SecurityPolicy, 0)
	} else {
		ans = ans[start:util.MinInt(end, len(ans))]
	}

	response.JSONOK(ctx, response.WithItems(ans),
		response.WithTotalItems(cnt),
		response.WithItemsPerPage(filter.Limit),
		response.WithStartIndex(filter.Offset))
}

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesec2 "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

type RejectAPI struct {
	Srv imagesec.TrustedImageService
}

// RSAGenerate 生成RSA密钥对
// @Summary 可信镜像
// @Title 生成RSA密钥对
// @Author liuyang@tensorsecurity.cn
// @Description 生成RSA密钥对
// @Tags image-reject
// @Param json body model.ImageRsa true "请求参数"
// @Success 200 {object} gin.Context
// @Router	/api/v1/imagereject/trustedImages/rsa [post]
func (r *RejectAPI) RSAGenerate(ctx *gin.Context) {
	var req = new(model.ImageRsa)
	err := ctx.BindJSON(req)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	list, _, err := r.Srv.RSAList(ctx, imagesec.RSAListParam{Name: req.Name}, nil)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if len(list) > 0 {
		response.JSONError(ctx, response.NewHttpError(http.StatusNotAcceptable, fmt.Errorf("rsa:%s is exist", req.Name)))
		return
	}

	result, err := r.Srv.RSAGenerate(ctx, req)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	targetRef := response.TargetRef{
		Name: req.Name,
		Link: "api/v2/containerSec/scanner/imagereject/trustedImages/rsa",
	}
	bys, err := json.Marshal(targetRef)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	ctx.Writer.WriteHeader(http.StatusOK)
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s_private.pem", req.Name))
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("Accept-Length", strconv.Itoa(len(result)))
	ctx.Header("targetref", string(bys))
	_, _ = ctx.Writer.Write(result)
}

// RSAUpdate 修改指定RSA密钥对
// @Summary 可信镜像
// @Title 修改指定RSA密钥对
// @Author liuyang@tensorsecurity.cn
// @Description 修改指定RSA密钥对
// @Tags image-reject
// @Param object body model.ImageRsa true "请求参数"
// @Param integer path id true "RSA id"
// @Success 200 {object} response.HTTPEnvelope{}
// @Failure 400 {object} response.HTTPEnvelope{}
// @Router	/api/v1/imagereject/trustedImages/rsa/:id [put]
func (r *RejectAPI) RSAUpdate(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("%s 不是一个有效的ID", ctx.Param("id")))
		return
	}

	var req = new(model.ImageRsa)
	if err := ctx.BindJSON(req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	if err := r.Srv.RSAUpdate(ctx, id, req); err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: req.Name,
		ID:   strconv.Itoa(int(id)),
		Link: "api/v2/containerSec/scanner/imagereject/trustedImages/rsa" + strconv.Itoa(int(id)),
	}))
}

// RSAList 获取RSA列表
// @Summary 可信镜像
// @Title 判断是否为可信镜像
// @Author liuyang@tensorsecurity.cn
// @Description 判断是否为可信镜像
// @Tags image-reject
// @Param integer query offset  true "偏移量"
// @Param integer query limit true "条数"
// @Success 200 {object} response.HTTPEnvelope{Data: []model}
// @Failure 400 {object} response.HTTPEnvelope{}
// @Router	/api/v1/imagereject/trustedImages/rsa [get]
func (r *RejectAPI) RSAList(ctx *gin.Context) {
	filter := imagesec2.GetFilterWithDefaultValue(ctx)
	filter = filter.SetSortCreatedAt().SetSortDesc()

	result, count, err := r.Srv.RSAList(ctx, imagesec.RSAListParam{}, filter)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItems(result), response.WithTotalItems(count))
}

// RSADetail 获取某个RSA详情
// @Summary 可信镜像
// @Title 判断是否为可信镜像
// @Author liuyang@tensorsecurity.cn
// @Description 判断是否为可信镜像
// @Tags image-reject
// @Param object body model.IsTrustedImagesReq true "请求参数"
// @Success 200 {object} response.HTTPEnvelope{Data: model.ImageRsa}
// @Router	/api/v1/imagereject/trustedImages/rsa/:id [get]
func (r *RejectAPI) RSADetail(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("%s 不是一个有效的ID", ctx.Param("id")))
		return
	}

	result, err := r.Srv.RSADetail(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithItem(result))
}

// RSADelete 删除某个RSA
// @Summary 可信镜像
// @Title 判断是否为可信镜像
// @Author liuyang@tensorsecurity.cn
// @Description 判断是否为可信镜像
// @Tags image-reject
// @Param integer path id true "RSA id"
// @Success 200 {object} response.HTTPEnvelope{}
// @Router	/api/v1/imagereject/trustedImages/rsa/:id [delete]
func (r *RejectAPI) RSADelete(ctx *gin.Context) {
	id, err := strconv.ParseInt(ctx.Param("id"), 10, 64)
	if err != nil {
		response.JSONError(ctx, fmt.Errorf("%s 不是一个有效的ID", ctx.Param("id")))
	}
	detail, err := r.Srv.RSADetail(ctx, id)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}
	if err := r.Srv.RSADelete(ctx, id); err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: detail.Name,
		ID:   strconv.Itoa(int(id)),
		Link: "api/v2/containerSec/scanner/imagereject/trustedImages/rsa/" + strconv.Itoa(int(id)),
	}))
}

// SignImageTrusted 签名镜像是否可信
// @Router /api/v1/imagereject/trustedImages/sign [post]
func (r *RejectAPI) SignImageTrusted(ctx *gin.Context) {
	var s = new(model.SignImageTrustedReq)
	if err := ctx.BindJSON(s); err != nil {
		response.JSONError(ctx, err)
		return
	}

	err := r.Srv.SignImageTrusted(ctx, s)
	if err != nil {
		response.JSONError(ctx, err)
		return
	}

	response.JSONOK(ctx, response.WithTarget(&response.TargetRef{
		Name: s.Image,
		ID:   s.Digest,
		Link: "api/v2/containerSec/scanner/imagereject/trustedImages/sign",
	}))
}

func NewRejectAPISrv(srv imagesec.TrustedImageService) *RejectAPI {
	return &RejectAPI{
		Srv: srv,
	}
}

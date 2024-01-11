package api

import (
	"context"
	"encoding/json"
	"github.com/dlclark/regexp2"
	param "github.com/oceanicdev/chi-param"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/security-rd/go-pkg/logging"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func (api *api) getEnableAssetsTags(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	tagList, err := resSvc.GetEnableAssetsTagList(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("get assetsTagList failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w, response.WithItems(tagList))
}

func (api *api) getAssetsTags(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	limit, offset := getLimitAndOffsetWithDefault(r)
	tagName := getNormalizedQueryParam(r, "tagName")
	if limit == 0 && offset == 0 {
		limit = 10
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	tagList, total, err := resSvc.GetAssetsTagListWithCount(ctx, tagName, offset, limit)
	if err != nil {
		logging.Get().Err(err).Msg("get assetsTagList failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w, response.WithItems(tagList), response.WithTotalItems(total))
}

func (api *api) changeAssetsTags(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	readAll, err := io.ReadAll(r.Body)
	if err != nil {
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}

	var request assets.ChangeAssetsTagStatus
	err = json.Unmarshal(readAll, &request)
	if err != nil {
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	err = resSvc.ChangeAssetsTagStatus(ctx, request)
	if err != nil {
		logging.Get().Err(err).Msg("get assetsTagList failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w)
}

func (api *api) getAssetsTagRelCountsById(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	tagId := getNormalizedURLParam(r, "tagId")
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	assetsRelCounts, err := resSvc.GetAssetsTagRelCounts(ctx, tagId)
	if err != nil {
		logging.Get().Err(err).Msg("get assetsTagList failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w, response.WithItem(*assetsRelCounts))
}

func (api *api) saveAssetsTag(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	readAll, err := io.ReadAll(r.Body)
	if err != nil {
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	var request dal.AssetsTagRelDetail
	err = json.Unmarshal(readAll, &request)
	if err != nil {
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	err = checkTagName(request.Tag.Name, request.Tag.Desc)
	if err != nil {
		RespAndLog(w, ctx, NewAnErrorWithErrMsg(http.StatusInternalServerError, err))
		return
	}
	request.Tag.Type = 0 //自定义
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	err = resSvc.SaveAssetsTagRel(ctx, &request)
	if err != nil {
		logging.Get().Err(err).Msg("get assetsTagList failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w)
}

func checkTagName(tagName string, tagDesc string) error {
	nameLen := utf8.RuneCountInString(tagName)
	if nameLen == 0 || nameLen > 15 {
		return errors.New("tag name's char length is limited to 1-15")
	}
	if tagName == "全部资产" || strings.ToLower(tagName) == "all assets" {
		return errors.New("tag name " + tagName + " is limit,try another name")
	}
	reg := `^[\u4e00-\u9fa5A-Za-z0-9_-]+$`
	compile, err := regexp2.Compile(reg, regexp2.None)
	if err != nil {
		return err
	}
	isMatch, err := compile.MatchString(tagName)
	if err != nil {
		return err
	}
	if !isMatch {
		return errors.New("合法字符范围：中文、英文大小写、数字、下划线、短线")
	}
	descLen := utf8.RuneCountInString(tagDesc)
	if descLen > 100 {
		return errors.New("tag desc's char length is limited to 0-100")
	}
	return nil
}

func (api *api) deleteAssetsTag(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	tagId := getNormalizedURLParam(r, "tagId")
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	err := resSvc.DeleteAssetsTag(ctx, tagId)
	if err != nil {
		logging.Get().Err(err).Msg("delete assetsTag failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w)
}

func (api *api) assetsChangeTags(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	readAll, err := io.ReadAll(r.Body)
	if err != nil {
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	var req dal.AssetsChangeTagsReq
	err = json.Unmarshal(readAll, &req)
	if err != nil {
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	err = resSvc.AssetsChangeTags(ctx, &req)
	logging.Get().Err(err).Msg("assets change assetsTag success")
	if err != nil {
		logging.Get().Err(err).Msg("assets change assetsTag failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w)
}

func (api *api) getAssetsCustomTags(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	customTags, err := resSvc.GetAssetsCustomTags(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("assets change assetsTag failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w, response.WithItems(customTags))
}

func (api *api) getAssetsCountInTag(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	tagId, _ := param.QueryString(r, "tagId")
	if tagId == "" {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("need tagName param")))
		return
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	customTags, err := resSvc.GetAssetsCountInTag(ctx, tagId)
	if err != nil {
		logging.Get().Err(err).Msg("assets change assetsTag failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w, response.WithItem(*customTags))
}

func (api *api) getAssetsByTag(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
	defer cancel()

	tagId, _ := param.QueryString(r, "tagId")
	if tagId == "" {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("need tagName param")))
		return
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		RespAndLog(w, ctx, NewAnError(http.StatusBadRequest, errors.New("service instance get error")))
		return
	}
	customTags, err := resSvc.GetAssetsCountInTag(ctx, tagId)
	if err != nil {
		logging.Get().Err(err).Msg("assets change assetsTag failed")
		RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
		return
	}
	response.Ok(w, response.WithItem(*customTags))
}

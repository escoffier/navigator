package api

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/hunter"
	"gitlab.com/piccolo_su/vegeta/cmd/kube-scanner-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (api *api) kubeHunter() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/scan", api.runKubeHunter())
		r.Get("/", api.getKubeHunterResult())
		r.Get("/status", api.getKubeHunterStatus())
	}
}

const (
	defaultHunterTimeout = time.Second * 5
	hunterAPIVersion     = "2.0"
)

func (api *api) runKubeHunter() http.HandlerFunc {
	type req struct {
		Cluster string `json:"cluster"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultHunterTimeout)
		defer cancel()

		var cliReq req
		err := util.DecodeJSONBody(w, r, &cliReq)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		service, ok := hunter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		err = service.Scan(ctx, cliReq.Cluster)
		if err != nil {
			if err == def.ErrTaskConflict {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err, "扫描正在进行中", "already in progress"))
				return
			}

			if err == hunter.ErrClusterNotFound {
				apperror.RespAndLog(w, ctx,
					apperror.NewCommonError(http.StatusBadRequest, err, "集群不存在", "cluster not found"))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(hunterAPIVersion))
	}
}

func (api *api) getKubeHunterResult() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultHunterTimeout)
		defer cancel()

		cluster, err := param.QueryString(r, "cluster")
		if err != nil || cluster == "" {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("not specify cluster")))
			return
		}

		service, ok := hunter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		result, err := service.GetClusterScanResult(ctx, cluster, string(lang.Language(ctx)))
		if err != nil {
			if err == def.ErrNoRecord {
				response.Ok(w, response.WithApiVersion(hunterAPIVersion), response.WithItem(model.KubeHunterTotalDisplay{}))
				return
			}

			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w, response.WithApiVersion(hunterAPIVersion), response.WithItem(*result))
	}
}

func (api *api) getKubeHunterStatus() http.HandlerFunc {
	type rsp struct {
		Status uint8 `json:"status"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), defaultHunterTimeout)
		defer cancel()

		cluster, err := param.QueryString(r, "cluster")
		if err != nil || cluster == "" {
			apperror.RespAndLog(w, ctx,
				apperror.NewInvalidArgError(http.StatusBadRequest, fmt.Errorf("not specify cluster")))
			return
		}

		service, ok := hunter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		inProgress, err := service.CheckTaskInProgress(ctx, cluster)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		var status uint8
		if inProgress {
			status = 1
		}

		response.Ok(w, response.WithApiVersion(accountAPIVersion), response.WithItem(rsp{Status: status}))
	}
}

const (
	reportKubeHunterResultTimeout = time.Second * 30
)

func (api *api) reportKubeHunterResult() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), reportKubeHunterResultTimeout)
		defer cancel()

		service, ok := hunter.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, ErrServiceNotReady)
			return
		}

		uuid := chi.URLParam(r, "uuid")
		if uuid == "" {
			apperror.RespAndLog(w, ctx, apperror.NewFieldError(http.StatusBadRequest, fmt.Errorf("no uuid")))
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		err = service.ReportKubeHunterResult(ctx, uuid, body)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}

		response.Ok(w)
	}
}

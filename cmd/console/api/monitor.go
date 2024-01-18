package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/monitor"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/security-rd/go-pkg/logging"
	"net/http"
	"strings"
	"time"
)

func (api *api) monitor() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/total", api.GetMonitorTotal)
		r.Get("/holmes", api.GetMonitorHolmes)
		r.Get("/component", api.GetMonitorComponent)
		r.Get("/refresh", api.RefreshMonitorComponent)
	}
}

func (api *api) GetMonitorTotal(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	svc, ok := monitor.GetService()
	if !ok {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
		return
	}
	total, err := svc.GetMonitorTotal()
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get monitor total failed, error : %w", err)))
		return
	}
	response.Ok(w, response.WithItem(total))
}

type monitorHolmes struct {
	Limit          int    `in:"query" name:"limit"`
	Offset         int    `in:"query" name:"offset"`
	PodName        string `in:"query" name:"name"`
	Version        string
	PodStatus      string
	ClusterKeyList []string `in:"query" name:"cluster_key"`
	NodeName       string   `in:"query" name:"node_name"`
}

func (req *monitorHolmes) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return err
	}
	req.Limit = limit
	req.Offset = offset
	req.PodName = getNormalizedQueryParam(r, "podName")
	req.Version = getNormalizedQueryParam(r, "version")
	req.PodStatus = getNormalizedQueryParam(r, "podStatus")
	clusterKeys := getNormalizedQueryParam(r, "clusterKey")
	if clusterKeys != "" {
		req.ClusterKeyList = strings.Split(clusterKeys, ",")
	}
	req.NodeName = getNormalizedQueryParam(r, "nodeName")
	return nil
}

func (api *api) GetMonitorHolmes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req := &monitorHolmes{}
	err := req.Render(r)
	if err != nil {
		logging.Get().Err(err).Msg("parse param error")
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("parse param error")))
		return
	}
	opt := dal.NewMonitorOption()
	if req.PodName != "" {
		opt.WhereLikeCondition["pod_name"] = req.PodName
	}
	if req.Version != "" {
		opt.WhereLikeCondition["version"] = req.Version
	}
	if req.PodStatus != "" {
		if len(strings.Split(req.PodStatus, ",")) != 2 {
			if req.PodStatus == dal.ContainerStatus_normal {
				opt.WhereEqCondition["pod_is_health"] = 0
			} else {
				opt.WhereEqCondition["pod_is_health"] = 1
			}
		}
	}
	if len(req.ClusterKeyList) > 0 {
		opt.WhereInCondition["cluster_key"] = req.ClusterKeyList
	}
	if req.NodeName != "" {
		opt.WhereLikeCondition["node_name"] = req.NodeName
	}

	svc, ok := monitor.GetService()
	if !ok {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
		return
	}

	holmesData, total, err := svc.GetMonitorHolmes(ctx, opt, req.Offset, req.Limit)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get monitor total failed, error : %w", err)))
		return
	}
	response.Ok(w, response.WithItems(holmesData), response.WithTotalItems(total), response.WithStartIndex(int64(req.Offset+len(holmesData))))
}

type monitorComponent struct {
	Limit          int `in:"query" name:"limit"`
	Offset         int `in:"query" name:"offset"`
	Component      string
	PodName        string `in:"query" name:"name"`
	Version        string
	PodStatus      string
	ClusterKeyList []string `in:"query" name:"cluster_key"`
	NodeName       string   `in:"query" name:"node_name"`
}

func (req *monitorComponent) Render(r *http.Request) error {
	limit, offset, err := getLimitAndOffset(r)
	if err != nil {
		return err
	}
	req.Limit = limit
	req.Offset = offset
	req.PodName = getNormalizedQueryParam(r, "podName")
	req.Component = getNormalizedQueryParam(r, "component")
	req.PodStatus = getNormalizedQueryParam(r, "podStatus")
	clusterKeys := getNormalizedQueryParam(r, "clusterKey")
	if clusterKeys != "" {
		req.ClusterKeyList = strings.Split(clusterKeys, ",")
	}
	req.NodeName = getNormalizedQueryParam(r, "nodeName")
	req.Version = getNormalizedQueryParam(r, "version")
	return nil
}

func (api *api) GetMonitorComponent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req := &monitorComponent{}
	err := req.Render(r)
	if err != nil {
		logging.Get().Err(err).Msg("parse param error")
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("parse param error")))
		return
	}
	opt := dal.NewMonitorOption()
	if req.Component == "" {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("param:component is empty")))
		return
	}
	opt.WhereEqCondition["app_label"] = req.Component
	if req.PodName != "" {
		opt.WhereLikeCondition["pod_name"] = req.PodName
	}
	if req.PodStatus != "" {
		if len(strings.Split(req.PodStatus, ",")) != 2 {
			if req.PodStatus == dal.ContainerStatus_normal {
				opt.WhereEqCondition["pod_is_health"] = 0
			} else {
				opt.WhereEqCondition["pod_is_health"] = 1
			}
		}
	}
	if len(req.ClusterKeyList) > 0 {
		opt.WhereInCondition["cluster_key"] = req.ClusterKeyList
	}
	if req.NodeName != "" {
		opt.WhereLikeCondition["node_name"] = req.NodeName
	}
	if req.Version != "" {
		opt.WhereLikeCondition["version"] = req.Version
	}

	svc, ok := monitor.GetService()
	if !ok {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
		return
	}

	holmesData, total, err := svc.GetMonitorComponent(ctx, opt, req.Offset, req.Limit)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get monitor total failed, error : %w", err)))
		return
	}
	response.Ok(w, response.WithItems(holmesData), response.WithTotalItems(total), response.WithStartIndex(int64(req.Offset+len(holmesData))))
}

func (api *api) RefreshMonitorComponent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	component := getNormalizedQueryParam(r, "component")
	if component == "" {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("param: component is empty")))
		return
	}
	svc, ok := monitor.GetService()
	if !ok {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
		return
	}

	data, total, err := svc.RefreshMonitorComponent(ctx, component)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("refresh  failed, error : %w", err)))
		return
	}
	response.Ok(w, response.WithItems(data), response.WithTotalItems(total))
}

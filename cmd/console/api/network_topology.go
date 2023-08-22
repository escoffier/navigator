package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/networktopo"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/model"
)

func (api *api) networkTopo() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/{direction}/cluster/{cluster}/namespace/{namespace}/kind/{kind}/resource/{resource}", api.listStreamInfo())
		r.Put("/topology", api.addNetTopology())
		r.Put("/topologies", api.addNetTopologiges())
		r.Get("/topology", api.getNetTopology())
	}
}

type OldNetworkFlow struct {
	UUID             uint32    `json:"uuid" gorm:"type:bigint;primarykey"`
	AssocKey         uint32    `json:"assoc_key" gorm:"-"`
	SrcCluster       string    `json:"src_cluster" gorm:"type:varchar(100);"`
	SrcNamespace     string    `json:"src_namespace" gorm:"type:varchar(100)"`
	SrcKind          string    `json:"src_kind" gorm:"type:varchar(100)"`
	SrcOwnerName     string    `json:"src_owner_name" gorm:"type:varchar(100);column:src_name;index:idx_flow_sname"`
	SrcContainerName string    `json:"src_container_name" gorm:"type:varchar(100)"`
	SrcProcess       string    `json:"src_process" gorm:"type:varchar(100)"`
	SrcPodName       string    `json:"src_pod_name"  gorm:"-"`
	SrcPid           int       `json:"src_pid" gorm:"-"`
	DstCluster       string    `json:"dst_cluster" gorm:"type:varchar(100)"`
	DstNamespace     string    `json:"dst_namespace" gorm:"type:varchar(100)"`
	DstKind          string    `json:"dst_kind" gorm:"type:varchar(100)"`
	DstOwnerName     string    `json:"dst_owner_name" gorm:"type:varchar(100);column:dst_name;index:idx_flow_dname"`
	DstContainerName string    `json:"dst_container_name" gorm:"type:varchar(100)"`
	DstProcess       string    `json:"dst_process" gorm:"type:varchar(100)"`
	DstPodName       string    `json:"dst_pod_name" gorm:"-"`
	DstPid           int       `json:"dst_pid" gorm:"-"`
	Proto            uint8     `json:"proto" gorm:"type:smallint"`
	DstPort          uint16    `json:"dst_port" gorm:"type:integer"`
	Status           int       `json:"status" gorm:"status"`
	CreatedAt        time.Time `json:"created_at" gorm:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" gorm:"updated_at"`
}

func NetflowsConvert(datas []*OldNetworkFlow) []*model.TensorNetworkFlow {
	rets := make([]*model.TensorNetworkFlow, len(datas))
	for i := 0; i < len(datas); i++ {
		value := &model.TensorNetworkFlow{
			UUID:             uint64(datas[i].UUID),
			AssocKey:         datas[i].AssocKey,
			SrcCluster:       datas[i].SrcCluster,
			SrcNamespace:     datas[i].SrcNamespace,
			SrcKind:          datas[i].SrcKind,
			SrcOwnerName:     datas[i].SrcOwnerName,
			SrcContainerName: datas[i].SrcContainerName,
			SrcProcess:       datas[i].SrcProcess,
			SrcPodName:       datas[i].SrcPodName,
			SrcPid:           datas[i].SrcPid,
			DstCluster:       datas[i].DstCluster,
			DstNamespace:     datas[i].DstNamespace,
			DstKind:          datas[i].DstKind,
			DstOwnerName:     datas[i].DstOwnerName,
			DstContainerName: datas[i].DstContainerName,
			DstProcess:       datas[i].DstProcess,
			DstPodName:       datas[i].DstPodName,
			DstPid:           datas[i].DstPid,
			Proto:            datas[i].Proto,
			DstPort:          datas[i].DstPort,
			Status:           datas[i].Status,
			CreatedAt:        datas[i].CreatedAt,
			UpdatedAt:        datas[i].UpdatedAt,
		}
		rets = append(rets, value)
	}
	return rets
}

func NetflowConvert(data *OldNetworkFlow) *model.TensorNetworkFlow {
	value := &model.TensorNetworkFlow{
		UUID:             uint64(data.UUID),
		AssocKey:         data.AssocKey,
		SrcCluster:       data.SrcCluster,
		SrcNamespace:     data.SrcNamespace,
		SrcKind:          data.SrcKind,
		SrcOwnerName:     data.SrcOwnerName,
		SrcContainerName: data.SrcContainerName,
		SrcProcess:       data.SrcProcess,
		SrcPodName:       data.SrcPodName,
		SrcPid:           data.SrcPid,
		DstCluster:       data.DstCluster,
		DstNamespace:     data.DstNamespace,
		DstKind:          data.DstKind,
		DstOwnerName:     data.DstOwnerName,
		DstContainerName: data.DstContainerName,
		DstProcess:       data.DstProcess,
		DstPodName:       data.DstPodName,
		DstPid:           data.DstPid,
		Proto:            data.Proto,
		DstPort:          data.DstPort,
		Status:           data.Status,
		CreatedAt:        data.CreatedAt,
		UpdatedAt:        data.UpdatedAt,
	}

	return value
}

// @Summary Find upstream services
// @Description list upstream services for specified service
// @Produce json
// @Router /upstream/cluster/{cluster}/namespace/{namespace}/kind/{kind}/resource/{resource} [get]
// @Param cluster url string true "k8s cluster"
// @Param  namespace url string true "namespace"
// @Param kind url string true "resource kind"
// @Param resource query string true "resource name"
func (api *api) listStreamInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
		defer cancel()

		cluster := chi.URLParam(r, "cluster")
		namespace := chi.URLParam(r, "namespace")
		kind := chi.URLParam(r, "kind")
		resource := chi.URLParam(r, "resource")
		if len(cluster) == 0 || len(namespace) == 0 || len(kind) == 0 || len(resource) == 0 {
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.New("missing cluster or namespace or kind or resource in url")))
			return
		}
		networkTopoService, _ := networktopo.Get(ctx)
		dir := chi.URLParam(r, "direction")
		var items []networktopo.ResourceInfo
		var total int64
		var err error
		switch dir {
		case "upstream":
			items, total, err = networkTopoService.ListUpstreamInfo(ctx, cluster, namespace, kind, resource, 24)
		case "downstream":
			items, total, err = networkTopoService.ListDownstreamInfo(ctx, cluster, namespace, kind, resource, 24)
		default:
			RespAndLog(w, ctx, NewFieldError(http.StatusBadRequest, errors.New("invalid direction")))
			return
		}

		if err != nil {
			RespAndLog(w, ctx, NewAnError(http.StatusInternalServerError, err))
			return
		}
		response.Ok(w, response.WithItems(items), response.WithTotalItems(total))
	}
}

// @Summary
// @Description add multiple net topologies
// @Produce json
// @Method PUT
// @Router /internal/platform/networkTopo/topologies
func (api *api) addNetTopologiges() http.HandlerFunc {
	type resp struct{}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var topologies []*OldNetworkFlow
		err := util.DecodeJSONBody(w, r, &topologies)
		if err != nil {
			RespAndLog(w, ctx, NewMalformedRequestError(http.StatusBadRequest, fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		networkTopoService, _ := networktopo.Get(ctx)
		values := NetflowsConvert(topologies)
		err = networkTopoService.AddNetTopologies(ctx, values)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to add net topology: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(resp{}))
	}
}

// @Summary
// @Description add a net topology
// @Produce json
// @Method PUT
// @Router /internal/platform/networkTopo/topology
func (api *api) addNetTopology() http.HandlerFunc {
	type resp struct {
		ID uint64 `json:"ID"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		topology := OldNetworkFlow{}
		err := util.DecodeJSONBody(w, r, &topology)
		if err != nil {
			RespAndLog(w, ctx,
				NewMalformedRequestError(http.StatusBadRequest,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		networkTopoService, _ := networktopo.Get(ctx)
		value := NetflowConvert(&topology)
		err = networkTopoService.AddNetTopology(ctx, value)
		if err != nil {
			RespAndLog(w, ctx,
				NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to add net topology: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(resp{
			ID: value.UUID,
		}))
	}
}

func (api *api) getNetTopology() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		networkTopoService, _ := networktopo.Get(ctx)
		i, err := param.QueryInt64(r, "time")
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("invalid time param: %v", err))
			return
		}

		t := time.Unix(i, 0)
		nts, count, err := networkTopoService.ListNetTopologies(ctx, t)
		if err != nil {
			RespAndLog(w, ctx, fmt.Errorf("couldn't list net topology: %v", err))
			return
		}
		response.Ok(w,
			response.WithItems(nts),
			response.WithTotalItems(count))
	}
}

package scap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/console/api/scap/internal"
	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

func (a *ApiServer) CronJobCreate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(string)

	var req scap.CronJob
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			fmt.Errorf("invalid request parameters")),
		)
		return
	}

	if err := internal.VerifyCronJob(&req); err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(http.StatusBadRequest, err))
		return
	}

	cron, err := internal.Cron(req.Cron)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(http.StatusBadRequest, err))
		return
	}

	var cronRecord = model.ScapCronRecord{
		Type:     scapType,
		Operator: model.GetUsernameFromContext(r.Context()),
		Cron:     cron,
		Status:   req.Status,
		PolicyID: req.PolicyID,
	}

	var cluster = make([]model.ScapClusterInfo, 0, len(req.ClusterInfos))
	for i := range req.ClusterInfos {
		cluster = append(cluster,
			model.ScapClusterInfo{
				ClusterKey:     req.ClusterInfos[i].ClusterKey,
				ClusterNodeIds: req.ClusterInfos[i].Nodes,
				IsAllNodes:     req.ClusterInfos[i].IsAllNodes,
			},
		)
	}

	err = a.service.CronJobSave(ctx, &cronRecord, cluster)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(http.StatusInternalServerError, err))
		return
	}

	response.Ok(w)
}

func (a *ApiServer) CronJobDetail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(string)

	cronJob, clusterInfo, err := a.service.CronJobDetail(ctx, scapType)
	if err != nil {
		apperror.RespAndLog(w, ctx,
			apperror.NewErrorWithCode(http.StatusInternalServerError, err))
		return
	}

	var resp scap.CronJobDetail

	// 当cronjob未设置时，直接返回一个空数据给前端
	if cronJob == nil {
		response.Ok(w, response.WithItem(resp))
		return
	}

	policy, _ := a.service.PolicyBrief(ctx, cronJob.PolicyID)

	resp.Cron = internal.ParseCron(cronJob.Cron)
	resp.Status = cronJob.Status
	resp.PolicyID = cronJob.PolicyID
	resp.PolicyName = policy.Name
	resp.ClusterInfos = make([]scap.ClusterInfoDetail, 0, len(clusterInfo))

	for i := range clusterInfo {
		resp.ClusterInfos = append(resp.ClusterInfos, scap.ClusterInfoDetail{
			ClusterInfo: scap.ClusterInfo{
				ClusterKey: clusterInfo[i].ClusterKey,
				IsAllNodes: clusterInfo[i].IsAllNodes,
				Nodes:      clusterInfo[i].ClusterNodeIds,
			},
			ClusterName: clusterInfo[i].ClusterName,
			NodeNames:   clusterInfo[i].ClusterNodeNames,
		})
	}

	response.Ok(w, response.WithItem(resp))
}

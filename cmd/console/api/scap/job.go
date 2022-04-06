package scap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/console/api/scap/internal"
	"gitlab.com/piccolo_su/vegeta/cmd/console/models/scap"
	scapservice "gitlab.com/piccolo_su/vegeta/cmd/console/service/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

// JobCreate 创建合规任务
func (a *ApiServer) JobCreate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*10)
	defer cancel()

	var scapType = r.Context().Value(sType).(uint8)
	var username = r.Context().Value(uName).(string)

	var req scap.JobReq
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusBadRequest,
			fmt.Errorf("invalid request parameters")),
		)
		return
	}

	if err := internal.VerifyJob(&req.Job); err != nil {
		apperror.RespAndLog(
			w,
			ctx,
			apperror.NewErrorWithCode(
				http.StatusBadRequest,
				err,
			),
		)
		return
	}

	err = a.service.CreateJob(ctx, &scapservice.Job{Job: req.Job, UserName: username, Type: scapType})
	if err != nil {
		apperror.RespAndLog(w, ctx, apperror.NewErrorWithCode(
			http.StatusInternalServerError,
			fmt.Errorf("create job failed")),
		)
		return
	}

	response.Ok(w)
}

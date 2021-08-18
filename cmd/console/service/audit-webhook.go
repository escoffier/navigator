package service

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/emicklei/go-restful"
	"k8s.io/apiserver/pkg/apis/audit"

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/k8saudit"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func setupWebHookRouter() http.Handler {
	container := restful.NewContainer()
	ws := new(restful.WebService)
	ws.Path("/audit").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	ws.Route(ws.POST("/webhook").To(AuditWebhook))
	container.Add(ws)
	return container
}

const (
	auditWebHookTimeout = time.Second * 3
	successResponse     = `{"message": "success"}`
)

func AuditWebhook(req *restful.Request, resp *restful.Response) {
	ctx, cancel := context.WithTimeout(req.Request.Context(), auditWebHookTimeout)
	defer cancel()

	body, err := ioutil.ReadAll(req.Request.Body)
	if err != nil {
		logging.GetLogger().Error().Msgf("read body err is: %v", err)
		_ = resp.WriteError(http.StatusBadRequest, err)
		return
	}

	var eventList audit.EventList
	err = json.Unmarshal(body, &eventList)
	if err != nil {
		logging.GetLogger().Error().Msgf("unmarshal failed with:%v,body is :%+v", err, string(body))
		_ = resp.WriteErrorString(http.StatusBadRequest, "parse event fail")
		return
	}

	var records = make([]*model.AuditRecord, len(eventList.Items))
	for i, item := range eventList.Items {
		records[i] = new(model.AuditRecord)
		records[i].Event = item
		if item.ObjectRef != nil {
			records[i].Namespace = item.ObjectRef.Namespace
			records[i].ResourceKind = item.ObjectRef.Resource
			records[i].ResourceName = item.ObjectRef.Name
		}

		if item.ResponseStatus != nil {
			records[i].ResponseStatusCode = item.ResponseStatus.Code
		}
	}

	service, ok := k8saudit.GetServiceInstance()
	if !ok {
		logging.GetLogger().Error().Msgf("k8s-audit service not ready")
		_ = resp.WriteErrorString(http.StatusInternalServerError, "service not ready")
		return
	}

	err = service.RecordAuditLog(ctx, records)
	if err != nil {
		logging.GetLogger().Err(err).Msg("RecordAuditLog fail")
		_ = resp.WriteError(http.StatusInternalServerError, err)
		return
	}

	resp.AddHeader("Content-Type", "application/json")
	_ = resp.WriteEntity(successResponse)
}

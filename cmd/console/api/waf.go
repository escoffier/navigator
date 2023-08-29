package api

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypto/x509"
	"encoding/pem"

	"github.com/go-chi/chi"
	"github.com/go-sql-driver/mysql"
	param "github.com/oceanicdev/chi-param"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/waf"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
)

func (api *api) waf() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/service", api.createService())
		r.Put("/service", api.updateService())
		r.Get("/services", api.getServices())
		r.Get("/service/{id}", api.getService())
		r.Delete("/service/{id}", api.deleteService())
		r.Post("/certCrt", api.uploadCertFiles())
		r.Post("/certKey", api.uploadCertFiles())
		r.Put("/config", api.config())
		r.Get("/config", api.getConfig())
		r.Post("/blackwhitelist", api.createBlackWhiteList())
		r.Put("/blackwhitelist", api.updateBlackWhiteList())
		r.Put("/blackwhitelist/enabling", api.enableBlackWhiteList())
		r.Delete("/blackwhitelist/{id}", api.deleteBlackWhiteList())
		r.Get("/blackwhitelists", api.getBlackWhiteLists())
		r.Get("/rules", api.listRules())
		r.Put("/rules", api.updateRules())
		r.Get("/attack/log/details", api.GetAttackLogDetails())
		r.Get("/attack/log/list", api.GetAttackLogsList())
		r.Get("/attack/log/rspPkg", api.GetAttackLogRspPkg())
		r.Get("/attack/classes", api.GetAttackClassesList())
	}
}

type Resp struct {
	Id           uint32 `json:"id"`
	Name         string `json:"name"`
	ClusterKey   string `json:"cluster_key"`
	Namespace    string `json:"namespace"`
	Kind         string `json:"kind"`
	ResourceName string `json:"resource_name"`
	UriPrefix    string `json:"uri_prefix"`
	Mode         string `json:"mode"`
	Host         string `json:"host"`
	Description  string `json:"description"`
	Protocol     string `json:"protocol"`
	AttackNumber uint64 `json:"attack_number"`
}

func convertWafErr(err error) error {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		if mysqlErr.Number == 1062 {
			err = apperror.NewWafNameDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated waf service name"))
		}
	} else if k8serr.IsAlreadyExists(err) {
		err = apperror.NewWafWorkloadDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated kube waf service name"))
	} else {
		err = apperror.NewAddWafServiceError(http.StatusInternalServerError, err)
	}
	return err
}

func convertExprErr(err error) error {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		if mysqlErr.Number == 1062 {
			err = apperror.NewExprNameDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated black/white list name"))
		}
	} else if k8serr.IsAlreadyExists(err) {
		err = apperror.NewExprNameDuplicateError(http.StatusInternalServerError, fmt.Errorf("duplicated kube waf service name"))
	} else {
		err = apperror.NewAddWafServiceError(http.StatusInternalServerError, err)
	}
	return err
}

func (api *api) createService() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}

		var req waf.WafRequest
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		logging.Get().Info().Msgf("waf request: %v", req)

		id, err := svc.AddWafService(ctx, &req)
		if err != nil {
			err = convertWafErr(err)
			apperror.RespAndLog(w, ctx, err)
			return
		}
		response.Ok(w, response.WithCustomField("id", id))
	}
}

func (api *api) updateService() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}

		var req waf.WafRequest
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		logging.Get().Info().Msgf("waf request: %v", req)

		err = svc.UpdateWafService(ctx, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to update waf service: %w", err)))
			return
		}
		response.Ok(w)
	}
}

func (api *api) uploadCertFiles() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		err := r.ParseMultipartForm(100 << 20)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("ParseMultipartForm fail, err:%w", err)))
			return
		}
		var fileName string
		if strings.Contains(r.URL.Path, "certCrt") {
			fileName = "tls-crt"
		} else if strings.Contains(r.URL.Path, "certKey") {
			fileName = "tls-key"
		} else {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				errors.New("invalid file")))
			return
		}

		file, header, err := r.FormFile(fileName)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewMalformedRequestError(http.StatusBadRequest,
				fmt.Errorf("read file fail, err:%w", err)))
			return
		}
		data, err := io.ReadAll(file)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}
		block, _ := pem.Decode([]byte(data))
		if block == nil {
			apperror.RespAndLog(w, ctx, fmt.Errorf("not PEM data"))
			return
		}

		if fileName == "tls-crt" {
			_, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				apperror.RespAndLog(w, ctx, err)
				return
			}
		}

		h := md5.New()
		h.Write(data)
		key := hex.EncodeToString(h.Sum(nil))

		logging.Get().Info().Msgf("filename:%s--hash: %s", header.Filename, key)
		err = svc.AddCertFile(ctx, key, data)
		if err != nil {
			apperror.RespAndLog(w, ctx, err)
			return
		}
		response.Ok(w, response.WithCustomField("id", key))
	}
}

func (api *api) getServices() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}
		clusterKeys, _ := param.QueryString(r, "cluster_key")
		namespace, _ := param.QueryString(r, "namespace")
		resourceName, _ := param.QueryString(r, "resource_name")
		name, _ := param.QueryString(r, "name")
		host, _ := param.QueryString(r, "host")
		modes, _ := param.QueryString(r, "mode")

		queryOpt := dal.ServiceQuery()
		if clusterKeys != "" {
			keys := strings.Split(clusterKeys, ",")
			queryOpt.WithInConditionCustom("cluster_key", keys)
		}
		if namespace != "" {
			queryOpt.WithFuzzyNamespace(namespace)
		}
		if name != "" {
			queryOpt.WithFuzzyName(name)
		}
		if host != "" {
			queryOpt.WithFuzzyHost(host)
		}
		if modes != "" {
			modeList := strings.Split(modes, ",")
			queryOpt.WithInConditionCustom("mode", modeList)
		}
		if resourceName != "" {
			queryOpt.WithFuzzyResource(resourceName)
		}

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		services, cnt, err := svc.GetWafServices(ctx, queryOpt, offset, limit)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("list waf services error %w", err)))
			return
		}
		items := make([]*Resp, 0, len(services))
		for _, s := range services {
			items = append(items, &Resp{
				Id:           s.ID,
				Name:         s.Name,
				ClusterKey:   s.ClusterKey,
				Namespace:    s.Namespace,
				Kind:         s.Kind,
				ResourceName: s.ResourceName,
				UriPrefix:    s.UriPrefix,
				Mode:         s.Mode,
				Host:         s.Host,
				Description:  s.Description,
				Protocol:     s.Protocol,
				AttackNumber: s.AttackNumber,
			})
		}
		response.Ok(w, response.WithItems(items), response.WithTotalItems(cnt), response.WithStartIndex(int64(offset+len(items))))
	}
}

func (api *api) getService() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		id := chi.URLParam(r, "id")
		logging.Get().Info().Msgf("id: %s", id)
		intId, err := strconv.Atoi(id)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("invalid waf service id:  %w", err)))
			return
		}

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		s, err := svc.GetWafService(ctx, uint32(intId))
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get waf service %d error %w", intId, err)))
			return
		}
		resp := &Resp{
			Id:           s.ID,
			Name:         s.Name,
			ClusterKey:   s.ClusterKey,
			Namespace:    s.Namespace,
			Kind:         s.Kind,
			ResourceName: s.ResourceName,
			UriPrefix:    s.UriPrefix,
			Mode:         s.Mode,
			Host:         s.Host,
			Description:  s.Description,
			Protocol:     s.Protocol,
			AttackNumber: s.AttackNumber,
		}
		response.Ok(w, response.WithItem(resp))
	}
}

func (api *api) deleteService() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		id := chi.URLParam(r, "id")
		logging.Get().Info().Msgf("id: %s", id)
		intId, err := strconv.Atoi(id)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("invalid waf service id:  %w", err)))
			return
		}

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		err = svc.DeleteSerivce(ctx, uint32(intId))
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("delete waf services error %w", err)))
			return
		}
		response.Ok(w)
	}
}

func (api *api) config() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}

		var config waf.WafConfig
		err := util.DecodeJSONBody(w, r, &config)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		logging.Get().Info().Msgf("waf config: %v", config)

		err = svc.Config(ctx, &config)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode config: %w", err)))
			return
		}
		response.Ok(w)
	}
}

func (api *api) getConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		config, err := svc.GetConfig(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get config error: %w", err)))
			return
		}
		response.Ok(w, response.WithItem(config))
	}
}

func (api *api) createBlackWhiteList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		var req waf.MatcherExpr
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		logging.Get().Info().Msgf("match expression request: %v", req)
		id, err := svc.AddMatchExpression(ctx, &req)
		if err != nil {
			err = convertExprErr(err)
			apperror.RespAndLog(w, ctx, err)
			return
		}
		response.Ok(w, response.WithCustomField("id", id))
	}
}

func (api *api) updateBlackWhiteList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		var req waf.MatcherExpr
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		logging.Get().Info().Msgf("match expression request: %v", req)
		err = svc.UpdateMatchExpression(ctx, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to update blackwhite list: %w", err)))
			return
		}
		response.Ok(w)
	}
}

func (api *api) enableBlackWhiteList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		var req waf.MatcherExpr
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		logging.Get().Info().Msgf("match expression request: %v", req)
		err = svc.EnableMatchExpression(ctx, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to update blackwhite list: %w", err)))
			return
		}
		response.Ok(w)
	}
}

func (api *api) getBlackWhiteLists() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		limit, offset, err := getLimitAndOffset(r)
		if err != nil {
			logging.Get().Err(err).Msgf("get limit or offset query error")
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusBadRequest, errors.New("no limit or offset given in params")))
			return
		}

		name, _ := param.QueryString(r, "name")
		status, _ := param.QueryString(r, "status")
		mode, _ := param.QueryString(r, "mode")
		expr, _ := param.QueryString(r, "expr")

		queryOpt := dal.MatchExprQuery()
		if status != "" {
			statusList := strings.Split(status, ",")
			if len(statusList) == 1 && statusList[0] != "" {
				switch status {
				case "0":
					queryOpt.WithStatus(0)
				case "1":
					queryOpt.WithStatus(1)
				}
			}
		}

		if name != "" {
			queryOpt.WithFuzzyName(name)
		}

		if mode != "" {
			modes := strings.Split(mode, ",")
			queryOpt.WithInConditionCustom("mode", modes)
		}

		if expr != "" {
			queryOpt.WithFuzzyExpr(expr)
		}

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		exprs, cnt, err := svc.GetMatchExpressions(ctx, queryOpt, offset, limit)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("get match expression error")))
			return
		}

		response.Ok(w, response.WithItems(exprs), response.WithTotalItems(cnt), response.WithStartIndex(int64(offset+len(exprs))))
	}
}

func (api *api) deleteBlackWhiteList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		id := chi.URLParam(r, "id")
		intID, err := strconv.Atoi(id)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to parse id: %w", err)))
		}
		err = svc.DeleteMatchExpression(ctx, uint32(intID))
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("delete black/white list err %w", err)))
			return
		}
		response.Ok(w)
	}
}

func (api *api) GetAttackLogDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}

		clusterKey, _ := param.QueryString(r, "cluster")
		uuid, _ := param.QueryString(r, "uuid")

		detail, err := svc.GetAttackLogDetails(ctx, clusterKey, uuid)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get attack logs details failed, error : %w", err)))
			return
		}
		response.Ok(w, response.WithItem(*detail))
	}
}

func (api *api) GetAttackLogRspPkg() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}

		uuid, _ := param.QueryString(r, "uuid")
		length, _ := param.QueryString(r, "length")

		rspPkg, err := svc.GetAttackLogRspPkg(ctx, uuid, length)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get attack logs failed, error : %w", err)))
			return
		}
		response.Ok(w, response.WithItem(*rspPkg))
	}
}

func (api *api) GetAttackLogsList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}

		var filter waf.AttackLogFilter
		id, _ := param.QueryString(r, "serviceId")
		filter.ServiceId, _ = strconv.ParseInt(id, 10, 64)
		filter.Limit, filter.Offset, _ = getLimitAndOffset(r)
		filter.Cluster, _ = param.QueryString(r, "cluster")
		filter.AttackUrl, _ = param.QueryString(r, "attackAddr")
		filter.AttackIp, _ = param.QueryString(r, "attackIp")
		filter.AttackType, _ = param.QueryString(r, "attackType")
		filter.AttackApp, _ = param.QueryString(r, "attackApp")
		filter.Token, _ = param.QueryString(r, "token")
		filter.Action, _ = param.QueryString(r, "action")
		stime, _ := param.QueryString(r, "startTime")
		filter.StartTime, _ = strconv.ParseInt(stime, 10, 64)
		etime, _ := param.QueryString(r, "endTime")
		filter.EndTime, _ = strconv.ParseInt(etime, 10, 64)

		rules, token, err := svc.GetAttackLogsList(ctx, &filter)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get attack logs failed, error : %w", err)))
			return
		}
		response.Ok(w, response.WithItems(rules), response.WithCustomField("token", token), response.WithTotalItems(int64(len(rules))))
	}
}

func (api *api) GetAttackClassesList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		rules, err := svc.GetAttackClassesList(ctx)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("get attack classes failed, error : %w", err)))
			return
		}
		response.Ok(w, response.WithItems(rules), response.WithTotalItems(int64(len(rules))))
	}
}

func (api *api) listRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		lang := r.Header.Get("Accept-Language")
		if lang == "" {
			lang = "zh"
		}

		name, _ := param.QueryString(r, "name")
		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		rules, err := svc.ListRules(ctx, lang, name)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("service waf instance get error: %w", err)))
			return
		}
		response.Ok(w, response.WithItems(rules))
	}
}

func (api *api) updateRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		svc, ok := waf.GetService(ctx)
		if !ok {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, errors.New("service waf instance get error")))
			return
		}
		var req waf.RuleRequest
		err := util.DecodeJSONBody(w, r, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx,
				apperror.NewAnError(http.StatusInternalServerError,
					fmt.Errorf("failed to decode json: %w", err)))
			return
		}
		err = svc.UpdateRules(ctx, &req)
		if err != nil {
			apperror.RespAndLog(w, ctx, apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("update waf rules error: %w", err)))
			return
		}
		response.Ok(w)
	}
}

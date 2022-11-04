package scap

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scap"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	sType = "scap-type"
)

type ApiServer struct {
	service *scap.Service
}

func NewAipServer(service *scap.Service) *ApiServer {
	return &ApiServer{service: service}
}

// InitRouter 初始化路由
func (a *ApiServer) InitRouter() func(chi.Router) {
	return func(r chi.Router) {

		r.Route("/{scap-type}", func(scapRouter chi.Router) {
			scapRouter.Use(a.ScapParseParamsMiddleware) // 使用中间件解析出 用户名 和 合规类型

			scapRouter.Route("/job", func(jobRouter chi.Router) {
				jobRouter.Post("/", a.JobCreate)
			})

			scapRouter.Route("/cronjob", func(cronjobRouter chi.Router) {
				cronjobRouter.Post("/", a.CronJobCreate)
				cronjobRouter.Get("/", a.CronJobDetail)
			})

			scapRouter.Route("/rule", func(ruleRouter chi.Router) {
				ruleRouter.Get("/", a.RuleBatch)
				ruleRouter.Get("/{id}", a.RuleDetail)
			})

			scapRouter.Route("/record", func(recordRouter chi.Router) {
				recordRouter.Get("/", a.RecordBatch)
			})

			scapRouter.Route("/policy", func(policyRouter chi.Router) {
				policyRouter.Get("/", a.PolicyBatch)
				policyRouter.Post("/", a.PolicyCreate)
				policyRouter.Put("/", a.PolicyUpdate)
				policyRouter.Get("/{id}", a.PolicyDetail)
				policyRouter.Delete("/{id}", a.PolicyDelete)
			})
		})
	}
}

// ScapParseParamsMiddleware 解析 参数中的 合规类型 和 用户信息
func (a *ApiServer) ScapParseParamsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkType := chi.URLParam(r, sType)
		if !model.ComplianceCheckType(checkType).IsValid() {
			apperror.RespAndLog(
				w,
				r.Context(),
				apperror.NewInvalidArgError(
					http.StatusBadRequest,
					fmt.Errorf("invalid checkType param value:%s,  (allowed: kube/docker/host)", checkType),
					apperror.Suberror{Location: "checkType", Message: "allowed: kube/docker/host"}),
			)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), sType, checkType))
		next.ServeHTTP(w, r)
	})
}

package api

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/security-rd/go-pkg/logging"
)

// 转发scanner中的接口
func (api *api) scanner() func(chi.Router) {
	return func(r chi.Router) {

		r.Get("/reportsByImageList", api.RedirectToScanner(true))
		r.Get("/reportsByImageOverview", api.RedirectToScanner(true))
		r.Get("/reportsByImageDetails", api.RedirectToScanner(true))
		// r.Post("/scan", api.scan())
		r.Post("/scanone", api.RedirectToScanner(true))

		r.Post("/harbor/scanAllNow", api.RedirectToScanner(true))
		r.Get("/harbor/scanConfig", api.harborScanConfig())
		r.Get("/harbor/scanStatus", api.RedirectToScanner(true))
		r.Get("/harbor/scanOneStatus", api.RedirectToScanner(true))
		r.Post("/harbor/abortScanAll", api.harborAbortScanAll())

		r.Get("/images/{imgDigest}/layers", api.RedirectToScanner())
		r.Get("/images/bases", api.RedirectToScanner())
		r.Post("/images/bases", api.RedirectToScanner())
		r.Delete("/images/bases/{imageID}", api.RedirectToScanner())
		r.Get("/images/app/{imageID}/bases", api.RedirectToScanner())
		r.Get("/images/base/{imageID}/apps", api.RedirectToScanner())
		r.Get("/images/env/{envName}", api.RedirectToScanner())
		r.Put("/images/env/{envName}", api.RedirectToScanner())

		r.Get("/layers/images/{imageId}/layers/{layerDigest}/info", api.RedirectToScanner())

		r.Get("/vulns/detail/{name}", api.RedirectToScanner())
		r.Get("/vulns/statistic", api.RedirectToScanner())
		r.Get("/vulns/all", api.RedirectToScanner())
		r.Get("/vulns/relation", api.RedirectToScanner())
		r.Put("/vulns/updata", api.RedirectToScanner())

		// r.Get("/register/projects/{projectName}", api.RedirectToScanner())
		r.Get("/register/registries", api.RedirectToScanner())
		r.Get("/register/registry/{id}", api.RedirectToScanner())
		r.Put("/register/registry/{id}", api.RedirectToScanner())
		r.Post("/register/registry", api.RedirectToScanner())
		r.Delete("/register/registry/{id}", api.RedirectToScanner())
		r.Get("/register/reg-type", api.RedirectToScanner())

		r.Get("/imagereject/result/file-checker", api.RedirectToScanner())
		r.Get("/imagereject/overview", api.RedirectToScanner())
		r.Get("/imagereject/reasons", api.RedirectToScanner())
		r.Get("/imagereject/images", api.RedirectToScanner())
		r.Get("/imagereject/whitelist", api.RedirectToScanner())
		r.Post("/imagereject/whitelist", api.RedirectToScanner())
		r.Delete("/imagereject/whitelist/{id}", api.RedirectToScanner())

		r.Get("/imagereject/policy/global", api.RedirectToScanner())
		r.Put("/imagereject/policy/global", api.RedirectToScanner())
		r.Post("/imagereject/policy/single", api.RedirectToScanner())
		r.Get("/imagereject/policy/single", api.RedirectToScanner())
		r.Put("/imagereject/policy/single/{id}", api.RedirectToScanner())
		r.Delete("/imagereject/policy/single/{id}", api.RedirectToScanner())

		r.Post("/imagereject/scanone/cicd", api.RedirectToScanner())
		r.Post("/imagereject/result/cicd", api.RedirectToScanner())
		r.Post("/imagereject/online_moniter", api.RedirectToScanner())

		r.Put("/tasks/{id}/status", api.RedirectToScanner())
		r.Get("/tasks/{id}/subtasks", api.RedirectToScanner())
		r.Get("/tasks", api.RedirectToScanner())

		r.Put("/scan-config/config/{scanConfigID}", api.RedirectToScanner())
		r.Get("/scan-config/config/global", api.RedirectToScanner())
		r.Post("/scan-config/strategy", api.RedirectToScanner())
		r.Put("/scan-config/strategy/{strategyID}", api.RedirectToScanner())
		r.Delete("/scan-config/strategy/{strategyID}", api.RedirectToScanner())
		r.Get("/scan-config/strategies", api.RedirectToScanner())
		r.Get("/scan-config/strategy/{strategyID}", api.RedirectToScanner())
		r.Get("/scan-config/strategy/open-sources", api.RedirectToScanner())
		r.Get("/scan-config/strategy/node-hostnames", api.RedirectToScanner())

		r.Get("/imagereject/trustedImages/rsa", api.RedirectToScanner())
		r.Get("/imagereject/trustedImages/rsa/{id}", api.RedirectToScanner())
		r.Post("/imagereject/trustedImages/rsa", api.RedirectToScanner())
		r.Put("/imagereject/trustedImages/rsa/{id}", api.RedirectToScanner())
		r.Delete("/imagereject/trustedImages/rsa/{id}", api.RedirectToScanner())
		r.Post("/imagereject/trustedImages/sign", api.RedirectToScanner())

		r.Post("/scan-report", api.RedirectToScanner())
		r.Delete("/scan-report/{id}", api.RedirectToScanner())
		r.Get("/scan-report/{id}", api.RedirectToScanner())
		r.Get("/scan-report", api.RedirectToScanner())
		r.Get("/scan-report/{id}/subtask", api.RedirectToScanner())
		r.Post("/scan-report/{id}/subtask", api.RedirectToScanner())
		r.Put("/scan-report/{id}", api.RedirectToScanner())
		r.Get("/scan-report/{id}/file/{sub_task_id}", api.RedirectToScanner())
	}
}

func (api *api) scannerOpenApi() func(router chi.Router) {
	return func(r chi.Router) {
		// r.Get("/*", api.ForwardScannerOpenApi())
		// r.Post("/*", api.ForwardScannerOpenApi())
		// r.Put("/*", api.ForwardScannerOpenApi())
		// r.Delete("/*", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/images/list", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Post("/images/scan/scantask", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/statistic/images", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/images/detail", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/images/layers", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/scanConfig/strategies", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Post("/scanConfig/strategies", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/scanConfig/strategies/{strategyName}", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Put("/scanConfig/strategies/{strategyName}", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Delete("/scanConfig/strategies/{strategyName}", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/statistic/vulns", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/vulns", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, 20)).
			Get("/vulns/{vulnName}", api.ForwardScannerOpenApi())
	}
}

func (api *api) ForwardScannerOpenApi() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pre := r.URL.String()
		logging.Get().Info().Str("openapi pre url", pre).Msg("ForwardScannerOpenApi")

		newUrl := fmt.Sprintf("%s%s", api.scannerURL,
			strings.Replace(pre, OpenAPIURLPrefix+"/containerSec/scanner", "/openapi/v1", 1))

		logging.Get().Info().Str("openapi new url", newUrl).Msg("ForwardScannerOpenApi")
		u, err := url.Parse(newUrl)
		if nil != err {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest, fmt.Errorf("count not parse the url:%s,error  %w", pre, err)))
			return
		}

		proxy := httputil.ReverseProxy{
			Director: func(request *http.Request) {
				request.URL = u
			},
		}
		proxy.ServeHTTP(w, r)
	}
}

// RedirectToScanner 转发scanner的请示
// 参数的意思是是否替换uri中的scanner字段，主要是为了兼容重构前的uri,之后的调用默认不传参数
func (api *api) RedirectToScanner(repaleceScannner ...bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /api/v2/containerSec/scanner/reportsByImageOverview
		// /api/v1/scan/reportsByImageOverview?offset=1

		pre := r.URL.String()
		logging.Get().WithContext(r.Context()).Infof("preUrl:%s", pre)
		var newUrl string

		if !strings.Contains(pre, "openapi") {
			if len(repaleceScannner) > 0 && repaleceScannner[0] {
				newUrl = fmt.Sprintf("%s%s", api.scannerURL,
					strings.Replace(pre, "/api/v2/containerSec/scanner", "/api/v1/scan", 1))
			} else {
				newUrl = fmt.Sprintf("%s%s", api.scannerURL,
					strings.Replace(pre, "/api/v2/containerSec/scanner", "/api/v1", 1))
			}
		} else {
			newUrl = fmt.Sprintf("%s%s", api.scannerURL,
				strings.Replace(pre, "/api/openapi/scanner", "/api/v1", 1))
		}

		u, err := url.Parse(newUrl)
		if nil != err {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest, fmt.Errorf("count not parse the url:%s,error  %w", pre, err)))
			return
		}

		proxy := httputil.ReverseProxy{
			Director: func(request *http.Request) {
				request.URL = u
			},
		}
		// ctx, cannel := context.WithTimeout(r.Context(), 600*time.Second)
		// defer cannel()
		// r = r.WithContext(ctx)
		proxy.ServeHTTP(w, r)
	}
}

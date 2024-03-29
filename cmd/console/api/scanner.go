package api

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"gitlab.com/security-rd/go-pkg/logging"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
)

// 转发scanner中的接口
func (api *api) scanner() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/harbor/scanConfig", api.harborScanConfig())
		// r.Get("/harbor/scanOneStatus", api.RedirectToScanner(true))
		r.Post("/harbor/abortScanAll", api.harborAbortScanAll())
		r.Get("/images/{imgDigest}/layers", api.RedirectToScanner())

		r.Delete("/images/bases/{imageID}", api.RedirectToScanner())
		r.Get("/images/app/{imageID}/bases", api.RedirectToScanner())
		r.Get("/images/base/{imageID}/apps", api.RedirectToScanner())
		r.Get("/images/env/{envName}", api.RedirectToScanner())
		r.Put("/images/env/{envName}", api.RedirectToScanner())

		r.Get("/images/verifyExistence", api.RedirectToScanner())
		r.Get("/images/existenceCount", api.RedirectToScanner())
		r.Get("/images/bin/whitelist", api.RedirectToScanner())
		r.Post("/images/bin/whitelist", api.RedirectToScanner())

		r.Get("/vulns/imageHistogram/{imageID}", api.RedirectToScanner())
		r.Get("/vulns/all", api.RedirectToScanner())
		r.Get("/vulns/relation", api.RedirectToScanner())
		r.Put("/vulns/updata", api.RedirectToScanner())
		r.Get("/vulns/imageVuln/vuln", api.RedirectToScanner())
		r.Get("/vulns/imageVuln/pkg", api.RedirectToScanner())
		r.Get("/vulns/imageVuln/language", api.RedirectToScanner())
		r.Get("/vulns/imageVuln/gobinary", api.RedirectToScanner())
		r.Get("/vulns/imageVuln/frame", api.RedirectToScanner())
		r.Post("/vulns/setVulnRisk", api.RedirectToScanner())

		r.Get("/imagereject/result/file-checker", api.RedirectToScanner())
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
		r.Post("/imagereject/online_moniter", api.RedirectToScanner())
		r.Put("/tasks/{id}/status", api.RedirectToScanner())
		r.Get("/tasks/{id}/subtasks", api.RedirectToScanner())
		r.Get("/tasks", api.RedirectToScanner())
		r.Post("/tasks/image", api.RedirectToScanner())
		r.Put("/scan-config/config/{scanConfigID}", api.RedirectToScanner())
		r.Get("/scan-config/config/global", api.RedirectToScanner())
		r.Post("/scan-config/strategy", api.RedirectToScanner())
		r.Put("/scan-config/strategy/{strategyID}", api.RedirectToScanner())
		r.Delete("/scan-config/strategy/{strategyID}", api.RedirectToScanner())
		r.Get("/scan-config/strategies", api.RedirectToScanner())
		r.Get("/scan-config/strategy/{strategyID}", api.RedirectToScanner())
		r.Get("/scan-config/strategy/open-sources", api.RedirectToScanner())
		r.Get("/scan-config/strategy/node-hostnames", api.RedirectToScanner())
		r.Get("/scan-config/strategy/projects", api.RedirectToScanner())
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

		r.Post("/ci/policy", api.RedirectToScanner())
		r.Get("/ci/policy", api.RedirectToScanner())
		r.Put("/ci/policy", api.RedirectToScanner())
		r.Delete("/ci/policy", api.RedirectToScanner())
		r.Get("/ci/policies", api.RedirectToScanner())
		r.Get("/ci/images", api.RedirectToScanner())
		r.Get("/ci/image", api.RedirectToScanner())
		r.Get("/ci/statistic/image", api.RedirectToScanner())
		r.Get("/ci/statistic/top5", api.RedirectToScanner())
		r.Get("/ci/vulns", api.RedirectToScanner())
		r.Get("/ci/pkgs", api.RedirectToScanner())
		r.Get("/ci/whitelist", api.RedirectToScanner())
		r.Post("/ci/whitelists", api.RedirectToScanner())
		r.Delete("/ci/whitelist", api.RedirectToScanner())
		r.Put("/ci/whitelists", api.RedirectToScanner())
		r.Post("/ci/result", api.RedirectToScanner())
		r.Get("/ci/webhook", api.RedirectToScanner())
		r.Post("/ci/webhook", api.RedirectToScanner())
		r.Put("/ci/webhook", api.RedirectToScanner())
		r.Get("/ci/webhook/record", api.RedirectToScanner())
		r.Get("/ci/vuln/detail", api.RedirectToScanner())
		r.Get("/ci/image/whitelist", api.RedirectToScanner())
		r.Get("/ci/sensitives", api.RedirectToScanner())
		r.Get("/ci/tidb/version", api.RedirectToScanner())
		r.Get("/ci/tidb/assets/{fileName}", api.RedirectToScanner())
		r.Get("/webshells/imageWebshell/webshell", api.RedirectToScanner())
		r.Get("/webshells/imageWebshell/detail", api.RedirectToScanner())
		r.Get("/webshells/imageWebshell/download", api.RedirectToScanner())
		r.Post("/webshells/imageWebshell/file", api.RedirectToScanner())

		r.Put("/db/update", api.RedirectToScanner())
		r.Put("/db/update/malicious", api.RedirectToScanner())
		r.Get("/db/version", api.RedirectToScanner())
		r.Get("/db/history", api.RedirectToScanner())

		// 仓库镜像改
		r.Post("/images/list", api.RedirectToScanner())
		r.Post("/images/assets/image", api.RedirectToScanner())
		r.Get("/images/overview", api.RedirectToScanner())
		r.Get("/images/resource", api.RedirectToScanner())
		r.Get("/images/related/image", api.RedirectToScanner())
		r.Get("/images/existenceCount", api.RedirectToScanner())  // 内部使用
		r.Get("/images/verifyExistence", api.RedirectToScanner()) // 内部使用
		r.Get("/images/sampleList", api.RedirectToScanner())      // 内部使用

		r.Get("/images/detail/base", api.RedirectToScanner())
		r.Get("/images/detail/issueStatistic", api.RedirectToScanner())
		r.Get("/images/detail/issueOverview", api.RedirectToScanner())
		r.Get("/images/detail/env", api.RedirectToScanner())
		r.Get("/images/detail/virus", api.RedirectToScanner())
		r.Get("/images/detail/layers", api.RedirectToScanner())
		r.Get("/images/detail/sensitiveFile", api.RedirectToScanner())
		r.Get("/images/detail/software", api.RedirectToScanner())
		r.Get("/images/detail/vulns/vuln", api.RedirectToScanner())
		r.Get("/images/detail/vulns/pkg", api.RedirectToScanner())
		r.Get("/images/detail/vulns/language", api.RedirectToScanner())
		r.Get("/images/detail/vulns/gobinary", api.RedirectToScanner())
		r.Get("/images/detail/vulns/frame", api.RedirectToScanner())
		r.Get("/images/detail/webshell", api.RedirectToScanner())
		r.Get("/images/vulns/vuln/detail", api.RedirectToScanner())
		r.Get("/images/vulns/vuln/constView", api.RedirectToScanner())
		r.Get("/images/webshell/detail", api.RedirectToScanner())
		r.Get("/images/sensitive/detail", api.RedirectToScanner())
		r.Get("/images/malware/detail", api.RedirectToScanner())
		r.Get("/images/webshell/content", api.RedirectToScanner())
		r.Get("/images/webshell/file", api.RedirectToScanner())
		r.Get("/images/sensitive/file", api.RedirectToScanner())
		r.Get("/images/license/file", api.RedirectToScanner())
		r.Get("/images/malware/file", api.RedirectToScanner())
		r.Post("/images/detail/riskInfo", api.RedirectToScanner())
		r.Get("/images/detail/baseImage", api.RedirectToScanner())
		r.Get("/images/detail/appImage", api.RedirectToScanner())
		r.Get("/images/detail/license", api.RedirectToScanner())
		r.Post("/images/baseImage", api.RedirectToScanner())
		r.Delete("/images/baseImage", api.RedirectToScanner())
		r.Get("/images/registryProject", api.RedirectToScanner())

		// 漏洞相关
		r.Get("/vulns/detail", api.RedirectToScanner())
		r.Get("/vulns/statistic", api.RedirectToScanner())
		r.Get("/vulns/list", api.RedirectToScanner())
		r.Get("/vulns/software", api.RedirectToScanner())
		r.Get("/vulns/topNImage", api.RedirectToScanner())
		r.Get("/vulns/query", api.RedirectToScanner())

		// 部署上线阻断
		r.Get("/deploy/reasonTop5", api.RedirectToScanner())
		r.Get("/deploy/whiteImage", api.RedirectToScanner())
		r.Post("/deploy/whiteImage", api.RedirectToScanner())
		r.Put("/deploy/whiteImage", api.RedirectToScanner())
		r.Delete("/deploy/whiteImage", api.RedirectToScanner())
		r.Post("/deploy/record", api.RedirectToScanner())
		r.Get("/deploy/overview", api.RedirectToScanner())
		r.Get("/deploy/blockTrend", api.RedirectToScanner())

		// 安全策略及镜像检测
		r.Post("/security/detect/policy", api.RedirectToScanner())
		r.Delete("/security/detect/policy", api.RedirectToScanner())
		r.Put("/security/detect/policy", api.RedirectToScanner())
		r.Get("/security/detect/policy/detail", api.RedirectToScanner())
		r.Get("/security/detect/policy/snapshot", api.RedirectToScanner())
		r.Get("/security/detect/policy/list", api.RedirectToScanner())

		// 扫描记录
		r.Put("/scanTask/image/scan/task/status", api.RedirectToScanner())
		r.Put("/scanTask/image/scan/subtask/reschedule", api.RedirectToScanner())
		r.Post("/scanTask/image/scan/task", api.RedirectToScanner())
		r.Get("/scanTask/image/scan/task/list", api.RedirectToScanner())
		r.Get("/scanTask/image/scan/subtask/list", api.RedirectToScanner())

		// 敏感文件规则
		r.Post("/config/scan/sensitive/rule", api.RedirectToScanner())
		r.Put("/config/scan/sensitive/rule", api.RedirectToScanner())
		r.Get("/config/scan/sensitive/rule/list", api.RedirectToScanner())
		r.Delete("/config/scan/sensitive/rule", api.RedirectToScanner())
		r.Get("/config/scan/license/list", api.RedirectToScanner())
		r.Get("/config/scan/license/detail", api.RedirectToScanner())

		// 配置
		r.Get("/config/scan/image", api.RedirectToScanner())
		r.Get("/config/view/const", api.RedirectToScanner())
		r.Put("/config/scan/image", api.RedirectToScanner())
		r.Get("/managementCenter/docs", api.RedirectToScanner())

		// 病毒库，漏洞库管理
		r.Post("/config/manage/db/vuln", api.RedirectToScanner())
		r.Post("/config/manage/db/avira", api.RedirectToScanner())
		r.Get("/config/manage/db/list", api.RedirectToScanner())

		// 节点及扫描器
		r.Get("/node/nodeInfo/list", api.RedirectToScanner())
		r.Get("/scannerInfo/list", api.RedirectToScanner())

		// 仓库管理及同步
		r.Post("/syncImage/startSync", api.RedirectToScanner())
		r.Get("/syncImage/syncProgress", api.RedirectToScanner())
		r.Get("/syncImage/syncStatus", api.RedirectToScanner())
		r.Get("/syncImage/registries", api.RedirectToScanner())
		r.Get("/syncImage/registry", api.RedirectToScanner())
		r.Put("/syncImage/registry", api.RedirectToScanner())
		r.Delete("/syncImage/registry", api.RedirectToScanner())
		r.Post("/syncImage/registry", api.RedirectToScanner())
		r.Get("/syncImage/regType", api.RedirectToScanner())
		r.Get("/syncImage/regions", api.RedirectToScanner())

		// 扫描任务
		r.Post("/task/image", api.RedirectToExport())
		r.Post("/task/scanTask", api.RedirectToExport())
		r.Post("/task/vuln", api.RedirectToExport())
		r.Post("/task/imageSearch", api.RedirectToExport())
		r.Get("/task/detail", api.RedirectToExport())
		r.Get("/task/list", api.RedirectToExport())
		r.Get("/task/download", api.RedirectToExport())

		// 这部分接口是内部使用接口，为了调试方便增加
		r.Get("/html/images", api.RedirectToExport())
		r.Get("/html/imageIdNames", api.RedirectToExport())
		r.Get("/html/riskOverView", api.RedirectToExport())
		r.Get("/html/imageRisk", api.RedirectToExport())
		r.Get("/html/imageVulns", api.RedirectToExport())
		r.Get("/html/exportVulns", api.RedirectToExport())
		r.Get("/html/imageVirus", api.RedirectToExport())

	}
}

// 转发scanner中的接口
func (api *api) export() func(chi.Router) {

	return func(r chi.Router) {
		r.Post("/task/image", api.RedirectToExport())
		r.Post("/task/scanTask", api.RedirectToExport())
		r.Post("/task/vuln", api.RedirectToExport())
		r.Post("/task/imageSearch", api.RedirectToExport())
		r.Post("/task/yaml", api.RedirectToExport())
		r.Post("/task/dockerfile", api.RedirectToExport())
		r.Get("/task/detail", api.RedirectToExport())
		r.Get("/task/list", api.RedirectToExport())
		r.Get("/task/download", api.RedirectToExport())
		r.Get("/task/checkScanTask", api.RedirectToExport())

		// 这部分接口是内部使用接口，为了调试方便增加
		r.Get("/html/images", api.RedirectToExport())
		r.Get("/html/imageIdNames", api.RedirectToExport())
		r.Get("/html/riskOverView", api.RedirectToExport())
		r.Get("/html/imageRisk", api.RedirectToExport())
		r.Get("/html/imageVulns", api.RedirectToExport())
		r.Get("/html/exportVulns", api.RedirectToExport())
		r.Get("/html/imageVirus", api.RedirectToExport())
	}
}

// 转发scanner中的接口
func (api *api) exportDownload() func(chi.Router) {
	return func(r chi.Router) {
		r.Get("/export/file/{filename}", api.RedirectToExportDownload()) // 文件下载转发
	}
}

func (api *api) scannerOpenApi() func(router chi.Router) {

	rate, err := strconv.Atoi(os.Getenv("OPENAPI_RATE_LIMIT_PER_MIN"))
	if err != nil || rate <= 0 {
		rate = 20
	}

	return func(r chi.Router) {
		// r.Get("/*", api.ForwardScannerOpenApi())
		// r.Post("/*", api.ForwardScannerOpenApi())
		// r.Put("/*", api.ForwardScannerOpenApi())
		// r.Delete("/*", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/images/assets/image", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/images/assets/running/digest", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/images/list", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/images/registryProject", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/images/scan/scantask", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/images/scan/scantask/v2", api.ForwardScannerOpenApi()) // Deprecated

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/statistic/images", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/images/detail", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/images/layers", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/scanConfig/strategies", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/scanConfig/strategies", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/scanConfig/strategies/{strategyName}", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Put("/scanConfig/strategies/{strategyName}", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Delete("/scanConfig/strategies/{strategyName}", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/statistic/vulns", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/vulns/list", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/vulns/detail", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/vulns/topNImage", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/ci/policies", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/ci/policy/{name}", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/ci/result", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/ci/tidb/version", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/ci/tidb/assets/{name}", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/ci/sign", api.ForwardScannerOpenApi())

		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/syncImage/startSync", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Post("/register/registry", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Put("/register/registry", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Delete("/register/registry", api.ForwardScannerOpenApi())
		r.With(RateLimitMiddleware(api.redisClient, int64(rate))).
			Get("/register/registries", api.ForwardScannerOpenApi())
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
		r.Host = u.Host
		proxy.ServeHTTP(w, r)
	}
}

// RedirectToScanner 转发scanner的请示
// 参数的意思是是否替换uri中的scanner字段，主要是为了兼容重构前的uri,之后的调用默认不传参数
func (api *api) RedirectToScanner() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pre := r.URL.String()
		var newUrl string

		newUrl = fmt.Sprintf("%s%s", api.scannerURL,
			strings.Replace(pre, "/api/v2/containerSec/scanner", "/api/v1", 1))

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
		r.Host = u.Host
		proxy.ServeHTTP(w, r)
	}
}

func (api *api) RedirectToExport() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /api/v2/containerSec/export/task/list
		// /openapi/v1/containerSec/export/task/list
		// /api/v1/export/task/list

		pre := r.URL.String()

		newUrl := fmt.Sprintf("%s%s", api.exportURL,
			strings.Replace(pre, NormalAPIURLPrefix+"/containerSec", "/api/v1", 1))

		if strings.Contains(pre, OpenAPIURLPrefix) {
			newUrl = fmt.Sprintf("%s%s", api.exportURL,
				strings.Replace(pre, OpenAPIURLPrefix+"/containerSec", "/api/v1", 1))
		}
		logging.Get().Debug().Str("newURL", newUrl).Msg("RedirectToExport")

		u, err := url.Parse(newUrl)
		if nil != err {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest, fmt.Errorf("count not parse the url:%s,error  %w", pre, err)))
			return
		}
		dialer := net.Dialer{
			Timeout:   30 * time.Minute,
			KeepAlive: 10 * time.Second,
		}

		roundTripper := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       9 * time.Minute,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		proxy := httputil.ReverseProxy{
			Director: func(request *http.Request) {
				request.URL = u
			},
			Transport: roundTripper,
		}
		r.Host = u.Host
		proxy.ServeHTTP(w, r)
	}
}

func (api *api) RedirectToExportDownload() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /api/v2/files/export/file/1111.zip
		// /api/v1/files/export/file/1111.zip

		pre := r.URL.String()
		newUrl := fmt.Sprintf("%s%s", api.exportURL,
			strings.Replace(pre, NormalAPIURLPrefix+"/files", "/api/v1", 1))

		u, err := url.Parse(newUrl)
		if nil != err {
			RespAndLog(w, r.Context(), NewFieldError(http.StatusBadRequest, fmt.Errorf("count not parse the url:%s,error  %w", pre, err)))
			return
		}

		dialer := net.Dialer{
			Timeout:   30 * time.Minute,
			KeepAlive: 10 * time.Second,
		}
		roundTripper := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       9 * time.Minute,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		proxy := httputil.ReverseProxy{
			Director: func(request *http.Request) {
				request.URL = u
			},
			Transport: roundTripper,
		}
		r.Host = u.Host
		proxy.ServeHTTP(w, r)
	}
}

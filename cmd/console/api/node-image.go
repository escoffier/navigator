package api

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-chi/chi"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
)

// 转发scanner中的接口
func (api *api) NodeImage() func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/images/list", api.NodeImageRedirectToScanner())
		// 镜像详情
		r.Get("/images/detail/base", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/issueStatistic", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/env", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/virus", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/layers", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/sensitiveFile", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/software", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/vulns/vuln", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/vulns/pkg", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/vulns/language", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/vulns/gobinary", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/vulns/frame", api.NodeImageRedirectToScanner())
		r.Get("/images/detail/webshell", api.NodeImageRedirectToScanner())
		r.Get("/images/vulns/vuln/detail", api.NodeImageRedirectToScanner())
		r.Get("/images/vulns/vuln/constView", api.NodeImageRedirectToScanner())
		r.Get("/images/webshell/detail", api.NodeImageRedirectToScanner())
		r.Get("/images/webshell/content", api.NodeImageRedirectToScanner())
		r.Get("/images/webshell/file", api.NodeImageRedirectToScanner())
		r.Get("/images/sensitive/file", api.NodeImageRedirectToScanner())
		r.Get("/images/malware/file", api.NodeImageRedirectToScanner())
		r.Get("/images/license/file", api.NodeImageRedirectToScanner())
		// 安全策略及镜像检测
		r.Post("/security/detect/policy", api.NodeImageRedirectToScanner())
		r.Delete("/security/detect/policy", api.NodeImageRedirectToScanner())
		r.Put("/security/detect/policy", api.NodeImageRedirectToScanner())
		r.Get("/security/detect/policy/detail", api.NodeImageRedirectToScanner())
		r.Get("/security/detect/policy/list", api.NodeImageRedirectToScanner())

		// 节点镜像的扫描记录
		r.Put("/scanTask/image/scan/task/status", api.NodeImageRedirectToScanner())
		r.Put("/scanTask/image/scan/subtask/reschedule", api.NodeImageRedirectToScanner())
		r.Post("/scanTask/image/scan/task", api.NodeImageRedirectToScanner())
		r.Get("/scanTask/image/scan/task/list", api.NodeImageRedirectToScanner())
		r.Get("/scanTask/image/scan/subtask/list", api.NodeImageRedirectToScanner())

		// 敏感文件规则
		r.Post("/config/scan/sensitive/rule", api.NodeImageRedirectToScanner())
		r.Put("/config/scan/sensitive/rule", api.NodeImageRedirectToScanner())
		r.Get("/config/scan/sensitive/rule/list", api.NodeImageRedirectToScanner())
		r.Delete("/config/scan/sensitive/rule", api.NodeImageRedirectToScanner())

		// 扫描配置
		r.Get("/config/scan/image", api.NodeImageRedirectToScanner())
		r.Get("/config/view/const", api.NodeImageRedirectToScanner())
		r.Put("/config/scan/image", api.NodeImageRedirectToScanner())
		// 节点列表
		r.Get("/node/nodeInfo/list", api.NodeImageRedirectToScanner())
	}
}

func (api *api) NodeImageRedirectToScanner() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// /api/v2/platform/nodeImage/config/scan/image
		// /api/v1/config/scan/image

		pre := r.URL.String()
		var newUrl string

		newUrl = fmt.Sprintf("%s%s", api.scannerURL,
			strings.Replace(pre, "/api/v2/platform/nodeImage", "/api/v1", 1))

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

package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
)

func isReadRequest(r *http.Request) bool {
	return r.Method == http.MethodGet ||
		r.URL.Path == "/api/v2/platform/sherlock/palace/events" ||
		r.URL.Path == "/api/v2/platform/sherlock/palace/signals" ||
		r.URL.Path == "/api/v2/platform/sherlock/palace/event/stats" ||
		r.URL.Path == "/api/v2/platform/sherlock/palace/signal/overview" ||
		r.URL.Path == "/api/v2/containerSec/ATTCK/ruleTemplates/rules" ||
		r.URL.Path == "/api/v2/platform/sherlock/hola/rules" ||
		r.URL.Path == "/api/v2/containerSec/scanner/images/list" ||
		r.URL.Path == "/api/v2/containerSec/scanner/images/assets/image" ||
		r.URL.Path == "/api/v2/containerSec/scanner/deploy/record" ||
		r.URL.Path == "/api/v2/containerSec/scanner/images/detail/riskInfo" ||
		r.URL.Path == "/api/v2/platform/sherlock/palace/attck/matrix" ||
		r.URL.Path == "/api/v2/platform/nodeImage/images/list" ||
		r.URL.Path == "/api/v2/containerSec/export/task/imageSearch" ||
		r.URL.Path == "/api/v2/containerSec/export/task/image" ||
		r.URL.Path == "/api/v2/containerSec/export/task/vuln" ||
		r.URL.Path == "/api/v2/platform/sherlock/palace/event/top/export"
}

const (
	moduleSkipAccess       = "skip_access"
	moduleManagementCenter = "management_center"
	moduleAudit            = "audit"
)

var accessUrlMap = map[string][]string{
	// 不需要权限验证的路由
	moduleSkipAccess: {
		"/api/v2/platform/sherlock/palace/event/notify/stats",
		"/api/v2/platform/sherlock/palace/task/status",
		"/api/v2/containerSec/scanner/vulns/statistic",
		"/api/v2/containerSec/scanner/reportsByImageOverview",
		"/api/v2/containerSec/scanner/imagereject/overview",
		"/api/v2/platform/apiscan/apis/count",
		"/api/v2/platform/nodeImage/images/list",
		"/api/v2/containerSec/scanner/vulns/topNImage",
		"/api/v2/containerSec/export/task/list",
		"/api/v2/containerSec/export/task/download",
	},
	moduleAudit: {
		"/api/v2/platform/assets",
		"/api/v2/platform/sherlock",

		"/api/v2/platform/processingCenter",
		"/api/v2/platform/naviAudit",
		"/api/v2/platform/audit",
	},
	// 平台
	// 仪表盘、风险探索、资产发现、事件中心
	"2": {
		"/api/v2/platform/assets",
		"/api/v2/platform/sherlock",
		"/api/v2/usercenter/userList",

		"/api/v2/platform/report",
		"/api/v2/platform/riskExplorer",
		"/api/v2/platform/processingCenter",
		"/api/v2/platform/networkTopo",
		"/api/v2/platform/apiscan",
		"/api/v2/platform/nodeImage/security/detect/policy/list",
		"/api/v2/platform/nodeImage/scanTask/image/scan/task/list",
		"/api/v2/containerSec/scanner/vulns/imageHistogram/",
		"/api/v2/containerSec/scanner/images/detail/riskInfo",
		"/api/v2/containerSec/scap/",
	},
	// 容器安全
	// ATT&CK、主动防御、偏移防御、镜像安全、合规检测、集群安全
	"3": {
		"/api/v2/platform/assets",
		"/api/v2/platform/sherlock",
		"/api/v2/usercenter/userList",

		"/api/v2/platform/processingCenter",
		"/api/v2/containerSec",
		"/api/v2/platform/drift",
		"/api/v2/platform/hunter",
		"/api/v2/platform/audit",
		"/api/v2/platform/nodeImage",
		"/api/v2/platform/version/ATTCKVersionList",
	},
	// 微隔离
	"4": {
		"/api/v2/platform/assets",
		"/api/v2/platform/sherlock",
		"/api/v2/usercenter/userList",

		"/api/v2/platform/processingCenter",
		"/api/v2/microseg",
	},
	// 管理中心
	moduleManagementCenter: {
		"/api/v2/platform/assets",

		"/api/v2/usercenter",
		"/api/v2/license",
		"/api/v2/platform/data",
		"/api/v2/platform/naviAudit",
		"/api/v2/platform/audit/config/syslog",
		"/api/v2/platform/version",
		"/api/v2/containerSec/ATTCK/conf",
		"/api/v2/containerSec/scanner/db/version",
		"/api/v2/containerSec/scanner/db/history",
		"/api/v2/containerSec/scanner/db/update",
		"/api/v2/containerSec/scanner/managementCenter/docs",
		"/api/v2/platform/configs",
		"/api/v2/containerSec/scanner/config/scan/sensitive/rule",
	},
}

func accessVerify(moduleID, currentURL string) bool {
	var moduleSLID []string
	if moduleID != "" {
		err := json.Unmarshal([]byte(moduleID), &moduleSLID)
		if err != nil {
			logging.Get().Warn().Err(err).Str("moduleID", moduleID).Msg(currentURL)
			return false
		}
	}

	currentURL = strings.ToLower(currentURL)
	for _, mid := range moduleSLID {
		accessListUrl := accessUrlMap[mid]
		for i := range accessListUrl {
			url := strings.ToLower(accessListUrl[i])
			if strings.HasPrefix(currentURL, url) {
				return true
			}
		}
	}

	return false
}

func Access(db *databases.RDBInstance) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userSession, ok := request.GetSessionFromContext(r.Context())
			if !ok {
				apperror.RespAndLog(w, r.Context(),
					apperror.NewSessionExpired(http.StatusUnauthorized,
						fmt.Errorf("user session not found in ctx")))
				return
			}

			urlPath := r.URL.Path
			hasAccess := accessVerify("[\""+moduleSkipAccess+"\"]", urlPath)
			if !hasAccess {
				switch userSession.Role {
				case model.RoleTypeSuperAdmin:
					// 超管角色拥有全部权限
					hasAccess = true
				case model.RoleTypePlatformAdmin:
					// 平台管理员仅有管理中心权限
					hasAccess = accessVerify("[\""+moduleManagementCenter+"\"]", urlPath)
				case model.RoleTypeAdmin:
					// 管理员通过配置的权限范围判定
					hasAccess = accessVerify(userSession.ModuleID, urlPath)
				case model.RoleTypeAudit:
					// 平台管理员仅有审计相关权限
					hasAccess = accessVerify("[\""+moduleAudit+"\"]", urlPath)
				case model.RoleTypeNormal:
					// 普通用户仅允许读，并过配置的权限范围判定
					hasAccess = isReadRequest(r) && accessVerify(userSession.ModuleID, urlPath)
				}
			}

			if !hasAccess {
				logging.Get().Debug().Str("username", userSession.Username).
					Str("account", userSession.Account).
					Str("role", string(userSession.Role)).
					Msgf("权限：%v， URL：%s", hasAccess, r.URL.Path)

				apperror.RespAndLog(w, r.Context(),
					apperror.NewNoAccess(http.StatusForbidden,
						fmt.Errorf("access invalid")))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

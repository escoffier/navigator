package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/go-chi/chi/middleware"
	v7 "github.com/olivere/elastic/v7"
	"github.com/rs/zerolog"
	"k8s.io/apimachinery/pkg/util/wait"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const JWTKeyUsername = "user_name"
const (
	editAction    = "编辑"
	createAction  = "新增"
	deleteAction  = "删除"
	enableAction  = "启用"
	disableAction = "停用"
	eAnddAction   = "启用/停用"
	importAction  = "导出"
	uploadAction  = "上传"
	processAction = "发起处置"
)

var routeAction *Router

type targetResponse struct {
	Target response.TargetRef `json:"target"`
}

type Store interface {
	store(ctx context.Context, event *model.NaviAuditEvent) error
}

func RequestLogger(store Store, queue *util.Queue) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			verb, detail, ok := getVerb(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			entry := NewLogEntry(r, store, queue)
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			buf := newLimitBuffer(80000)
			ww.Tee(buf)

			t1 := time.Now()

			defer func() {
				if !needAudit(ww) {
					return
				}
				data := map[string]interface{}{
					"verb":   verb,
					"detail": detail,
				}

				var respBody []byte
				var err error
				contentType := ww.Header().Get("Content-Type")
				if strings.Contains(contentType, "application/json") {
					respBody, err = ioutil.ReadAll(buf)
					if err == nil && len(respBody) > 0 {
						data["body"] = respBody
						objName := getObjectName(respBody)
						data["objName"] = objName
						detail, _ = generateDetail(detail, objName)
						data["detail"] = detail
					}
				} else {
					target := ww.Header().Get("targetref")
					if target != "" {
						targetRef := response.TargetRef{}
						err := json.Unmarshal([]byte(target), &targetRef)
						if err == nil {
							data["objName"] = targetRef.Name
							detail, _ = generateDetail(detail, targetRef.Name)
							data["detail"] = detail
						}
					}
				}
				entry.Write(ww.Status(), ww.BytesWritten(), ww.Header(), time.Since(t1), data)
			}()

			next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
		}
		return http.HandlerFunc(fn)
	}
}

func generateDetail(detail, objName string) (string, error) {
	tpl := template.Must(template.New("detail").Parse(detail))
	var buf bytes.Buffer
	err := tpl.Execute(&buf, objName)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func sendLog(store Store, queue *util.Queue) {
	stopChan := make(chan struct{})
	wait.Until(func() {
		for {
			item, ok := queue.Pop()
			if !ok {
				return
			}
			auditEvt, ok := item.(*model.NaviAuditEvent)
			if !ok {
				return
			}
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
				defer cancel()
				err := store.store(ctx, auditEvt)

				if err != nil {
					return
				}
			}()
		}
	}, time.Second*3, stopChan)

}

func NewLogEntry(r *http.Request, store Store, queue *util.Queue) middleware.LogEntry {
	entry := &LogEntry{
		auditEvt: requestLogFields(r),
		logQueue: queue,
		store:    store,
	}
	return entry
}

type LogEntry struct {
	auditEvt *model.NaviAuditEvent
	es       *v7.Client
	logQueue *util.Queue
	store    Store
}

func (e *LogEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	resp := &model.HttpResponse{
		Status:  status,
		Bytes:   bytes,
		Elapsed: float64(elapsed.Nanoseconds()) / 1000000.0, // in milliseconds
	}

	extraData, _ := extra.(map[string]interface{})
	body, ok := extraData["body"]
	if ok {
		resp.Body = string(body.([]byte))
	}
	verb, _ := extraData["verb"]
	detail, _ := extraData["detail"]
	objName, ok := extraData["objName"]
	if ok && objName != nil {
		if e.auditEvt.MetaData == nil {
			e.auditEvt.MetaData = make(map[string]interface{})
		}
		e.auditEvt.MetaData["objName"] = objName
	}
	if len(header) > 0 {
		resp.Header = headerLogField(header)
	}

	e.auditEvt.HttpResponse = resp
	e.auditEvt.Verb = verb.(string)
	e.auditEvt.Detail = detail.(string)

	if e.auditEvt.HttpRequest.Path == "/api/v2/usercenter/login" {
		name := objName.(string)
		if e.auditEvt.User == nil {
			e.auditEvt.User = &model.UserInfo{
				Name: name,
			}
		} else {
			e.auditEvt.User.Name = name
		}
	}

	if e.logQueue.Len() < maxQueueLen {
		e.logQueue.Add(e.auditEvt)
	}
}

func (e *LogEntry) Panic(v interface{}, stack []byte) {
}

func getVerb(r *http.Request) (string, string, bool) {
	path := r.URL.Path
	fn, params, _ := routeAction.Lookup(r.Method, path)
	if fn != nil {
		r1, r2 := fn(params)
		return r1, r2, true
	}
	return "", "", false
}

func requestLogFields(r *http.Request) *model.NaviAuditEvent {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	requestURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)

	contentType := r.Header.Get("Content-Type")
	var bodyStr string
	if contentType == "application/json" {
		body, err := ioutil.ReadAll(r.Body)
		if err == nil && len(body) > 0 {
			bodyStr = string(body)
			b := make([]byte, len(body))
			copy(b, body)
			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		}
	}

	remoteIP := r.Header.Get("X-Forwarded-For")
	if remoteIP == "" {
		remoteIP = r.Header.Get("X-Real-IP")
		if remoteIP == "" {
			remoteIP = r.RemoteAddr
		}
	}
	request := &model.HttpRequest{
		RequestURL: requestURL,
		Method:     r.Method,
		Path:       r.URL.Path,
		Proto:      r.Proto,
		RemoteIP:   remoteIP,
		Body:       bodyStr,
	}

	var requestID string
	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		requestID = reqID
	}

	userName := model.GetUsernameFromContext(r.Context())
	user := &model.UserInfo{Name: userName}

	return &model.NaviAuditEvent{
		RequestID:   requestID,
		User:        user,
		HttpRequest: request,
		Timestamp:   time.Now().UnixMilli(),
		MetaData:    nil,
	}
}

func headerLogField(header http.Header) map[string]string {
	headerField := map[string]string{}
	for k, v := range header {
		k = strings.ToLower(k)
		switch {
		case len(v) == 0:
			continue
		case len(v) == 1:
			headerField[k] = v[0]
		default:
			headerField[k] = fmt.Sprintf("[%s]", strings.Join(v, "], ["))
		}
		if k == "authorization" || k == "cookie" || k == "set-cookie" {
			headerField[k] = "***"
		}
	}
	return headerField
}

func statusLevel(status int) zerolog.Level {
	switch {
	case status <= 0:
		return zerolog.WarnLevel
	case status < 400: // for codes in 100s, 200s, 300s
		return zerolog.InfoLevel
	case status >= 400 && status < 500:
		return zerolog.WarnLevel
	case status >= 500:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

func statusLabel(status int) string {
	switch {
	case status >= 100 && status < 300:
		return "OK"
	case status >= 300 && status < 400:
		return "Redirect"
	case status >= 400 && status < 500:
		return "Client Error"
	case status >= 500:
		return "Server Error"
	default:
		return "Unknown"
	}
}

func getObjectName(body []byte) string {
	resp := &targetResponse{}
	err := json.Unmarshal(body, resp)
	if err != nil {
		return ""
	}
	return resp.Target.Name
}

func needAudit(w middleware.WrapResponseWriter) bool {
	status := w.Status()
	if status < 400 {
		return true
	}
	return false
}

func init() {
	routeAction = newRouter()
	// 平台报告
	routeAction.POST("/api/v2/platform/report/template", func(params Params) (string, string) {
		return createAction, "新增平台报告{{.}}"
	})
	routeAction.PUT("/api/v2/platform/report/template", func(params Params) (string, string) {
		return editAction, "编辑平台报告{{.}}"
	})
	routeAction.DELETE("/api/v2/platform/report/template", func(params Params) (string, string) {
		return deleteAction, "删除平台报告{{.}}"
	})
	routeAction.GET("/api/v2/platform/report/recordDetail", func(params Params) (string, string) {
		return importAction, "导出平台报告{{.}}"
	})

	// 主动防御
	routeAction.POST("/api/v2/containerSec/watson/baitService", func(params Params) (string, string) {
		return editAction, "编辑诱捕服务{{.}}"
	})
	routeAction.PUT("/api/v2/containerSec/watson/baitService", func(params Params) (string, string) {
		return createAction, "新增诱捕服务{{.}}"
	})
	routeAction.DELETE("/api/v2/containerSec/watson/baitService", func(params Params) (string, string) {
		return deleteAction, "删除诱捕服务{{.}}"
	})

	// 用户登录
	routeAction.POST("/api/v2/usercenter/login", func(params Params) (string, string) {
		return "登录", "登录"
	})

	// 资产发现
	routeAction.POST("/api/v2/platform/assets/namespace", func(params Params) (string, string) {
		return editAction, "编辑命名空间{{.}}"
	})
	routeAction.POST("/api/v2/platform/assets/resource/userData", func(params Params) (string, string) {
		return editAction, "编辑资源{{.}}"
	})

	// 事件中心
	routeAction.POST("/api/v2/platform/processingCenter/record", func(params Params) (string, string) {
		return processAction, "对Pod: {{.}}发起处置"
	})
	routeAction.POST("/api/v2/platform/processingCenter/record/action", func(params Params) (string, string) {
		return processAction, "对Pod: {{.}}发起处置"
	})
	routeAction.POST("/api/v2/platform/eventsCenter/config", func(params Params) (string, string) {
		return editAction, "编辑通知配置"
	})
	routeAction.POST("/api/v2/platform/eventsCenter/config/syslog", func(params Params) (string, string) {
		return editAction, "编辑Syslog导出"
	})

	// ATT&CK
	routeAction.POST("/api/v2/containerSec/ATTCK/ruleSwitch", func(params Params) (string, string) {
		return "启用/停用", "启/停用检测规则"
	})

	// 微隔离
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/resourceTag/infras", func(params Params) (string, string) {
		return editAction, "编辑资源配置"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/resourceTag/gateways", func(params Params) (string, string) {
		return editAction, "编辑资源配置"
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/kinds/:kind/resources/:resource/policy", func(params Params) (string, string) {
		return editAction, "编辑资源{{.}}的隔离策略"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/kinds/:kind/resources/:resource/policy/enabling", func(params Params) (string, string) {
		return "启用/停用", "启/停用资源{{.}}的隔离策略"
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments/:segment/policy", func(params Params) (string, string) {
		return editAction, "编辑资源组{{.}}的隔离策略"
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments", func(params Params) (string, string) {
		return createAction, "新增资源组{{.}}"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments/:segment", func(params Params) (string, string) {
		return editAction, "编辑资源组{{.}}"
	})
	routeAction.DELETE("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments/:segment", func(params Params) (string, string) {
		return deleteAction, "删除资源组{{.}}"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments/:segment/policy/enabling", func(params Params) (string, string) {
		return "启用/停用", "启/停用资源组{{.}}策略"
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/nsgrps", func(params Params) (string, string) {
		return createAction, "新增命名空间组{{.}}"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/nsgrps/:nsgrp", func(params Params) (string, string) {
		return editAction, "编辑命名空间组{{.}}"
	})
	routeAction.DELETE("/api/v2/microseg/clusters/:clusterKey/nsgrps/:nsgrp", func(params Params) (string, string) {
		return deleteAction, "删除命名空间组{{.}}"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/nsgrps/:nsgrp/policy/enabling", func(params Params) (string, string) {
		return "启用/停用", "启/停用命名空间组{{.}}策略"
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/tenants", func(params Params) (string, string) {
		return createAction, "新增租户{{.}}"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/tenants/:tenant", func(params Params) (string, string) {
		return editAction, "编辑租户{{.}}"
	})
	routeAction.DELETE("/api/v2/microseg/clusters/:clusterKey/tenants/:tenant", func(params Params) (string, string) {
		return deleteAction, "删除租户{{.}}"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/tenants/:tenant/policy/enabling", func(params Params) (string, string) {
		return "启用/停用", "启停租户{{.}}策略"
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/logicclusters", func(params Params) (string, string) {
		return createAction, "新增逻辑集群{{.}}"
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/logicclusters/:logiccluster", func(params Params) (string, string) {
		return editAction, "编辑逻辑集群{{.}}"
	})
	routeAction.DELETE("/api/v2/microseg/clusters/:clusterKey/logicclusters/:logiccluster", func(params Params) (string, string) {
		return deleteAction, "删除逻辑集群{{.}}"
	})

	// 镜像安全
	routeAction.POST("/api/v2/containerSec/scanner/scan-config/strategy", func(params Params) (string, string) {
		return createAction, "新增扫描策略{{.}}"
	})
	routeAction.PUT("/api/v2/containerSec/scanner/scan-config/strategy/:strategyID", func(params Params) (string, string) {
		return editAction, "编辑扫描策略{{.}}"
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/scan-config/strategy/:strategyID", func(params Params) (string, string) {
		return deleteAction, "删除扫描策略{{.}}"
	})

	routeAction.POST("/api/v2/containerSec/scanner/imagereject/trustedImages/rsa", func(params Params) (string, string) {
		return createAction, "新增密钥{{.}}"
	})
	routeAction.PUT("/api/v2/containerSec/scanner/imagereject/trustedImages/rsa/:id", func(params Params) (string, string) {
		return editAction, "编辑密钥{{.}}"
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/imagereject/trustedImages/rsa/:id", func(params Params) (string, string) {
		return deleteAction, "删除密钥{{.}}"
	})

	routeAction.PUT("/api/v2/containerSec/scanner/scan-config/config/:scanConfigID", func(params Params) (string, string) {
		return editAction, "编辑扫描配置"
	})

	routeAction.POST("/api/v2/containerSec/scanner/scan-report", func(params Params) (string, string) {
		return createAction, "新增镜像扫描报告{{.}}"
	})
	routeAction.PUT("/api/v2/containerSec/scanner/scan-report/:id", func(params Params) (string, string) {
		return editAction, "编辑镜像扫描报告{{.}}"
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/scan-report/:id", func(params Params) (string, string) {
		return deleteAction, "删除镜像扫描报告{{.}}"
	})

	routeAction.POST("/api/v2/containerSec/scanner/register/registry", func(params Params) (string, string) {
		return createAction, "新增镜像仓库{{.}}"
	})
	routeAction.PUT("/api/v2/containerSec/scanner/register/registry/:id", func(params Params) (string, string) {
		return editAction, "编辑镜像仓库{{.}}"
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/register/registry/:id", func(params Params) (string, string) {
		return deleteAction, "删除镜像仓库{{.}}"
	})

	routeAction.POST("/api/v2/containerSec/scanner/images/bases", func(params Params) (string, string) {
		return createAction, "新增基础镜像{{.}}至基础镜像列表"
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/images/bases/:id", func(params Params) (string, string) {
		return deleteAction, "删除基础镜像{{.}}出基础镜像列表"
	})

	routeAction.POST("/api/v2/containerSec/scanner/tasks/image", func(params Params) (string, string) {
		return createAction, "新增镜像扫描任务"
	})

	routeAction.POST("/api/v2/containerSec/scanner/imagereject/whitelist", func(params Params) (string, string) {
		return createAction, "新增镜像{{.}}至阻断白名单"
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/imagereject/whitelist/:id", func(params Params) (string, string) {
		return deleteAction, "删除镜像{{.}}出阻断白名单"
	})

	routeAction.PUT("/api/v2/containerSec/scanner/imagereject/policy/global", func(params Params) (string, string) {
		return editAction, "编辑阻断节点配置"
	})

	routeAction.POST("/api/v2/containerSec/scanner/imagereject/policy/single", func(params Params) (string, string) {
		return createAction, "新增阻断策略{{.}}"
	})
	routeAction.PUT("/api/v2/containerSec/scanner/imagereject/policy/single/:id", func(params Params) (string, string) {
		return editAction, "编辑阻断策略{{.}}"
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/imagereject/policy/single/:id", func(params Params) (string, string) {
		return deleteAction, "删除阻断策略{{.}}"
	})
	routeAction.PUT("/api/v2/containerSec/scanner/tasks/:id/status", func(params Params) (string, string) {
		return editAction, "编辑镜像扫描任务"
	})

	routeAction.POST("/api/v2/containerSec/scanner/ci/policy", func(params Params) (string, string) {
		return createAction, "新增CI策略{{.}}"
	})

	routeAction.PUT("/api/v2/containerSec/scanner/ci/policy", func(params Params) (string, string) {
		return editAction, "编辑CI策略{{.}}"
	})

	routeAction.DELETE("/api/v2/containerSec/scanner/ci/policy", func(params Params) (string, string) {
		return deleteAction, "删除CI策略{{.}}"
	})

	routeAction.POST("/api/v2/containerSec/scanner/ci/whitelists", func(params Params) (string, string) {
		return createAction, "新增CI白名单{{.}}"
	})

	routeAction.PUT("/api/v2/containerSec/scanner/ci/whitelists", func(params Params) (string, string) {
		return editAction, "编辑CI白名单{{.}}"
	})

	routeAction.DELETE("/api/v2/containerSec/scanner/ci/whitelist", func(params Params) (string, string) {
		return deleteAction, "删除CI白名单{{.}}"
	})

	routeAction.PUT("/api/v2/containerSec/scanner/ci/webhook", func(params Params) (string, string) {
		return editAction, "编辑CIWebhook{{.}}"
	})

	// 合规检测
	routeAction.POST("/api/v2/containerSec/scap/v2/:scapType/cronjob", func(params Params) (string, string) {
		scapType := model.ComplianceCheckType(params.ByName("scapType"))
		checkTypeName := ""
		switch scapType {
		case model.ComplianceCheckTargetTypeKube:
			checkTypeName = "编排软件"
		case model.ComplianceCheckTargetTypeDocker:
			checkTypeName = "Docker"
		case model.ComplianceCheckTargetTypeHost:
			checkTypeName = "主机"
		}
		return editAction, "编辑 " + checkTypeName + " 扫描配置"
	})

	routeAction.POST("/api/v2/containerSec/scap/v2/:scapType/job", func(params Params) (string, string) {
		checkType := model.ComplianceCheckType(params.ByName("scapType"))
		var checkTypeName string
		switch checkType {
		case model.ComplianceCheckTargetTypeKube:
			checkTypeName = "编排软件"
		case model.ComplianceCheckTargetTypeDocker:
			checkTypeName = "Docker"
		case model.ComplianceCheckTargetTypeHost:
			checkTypeName = "主机"
		}
		return createAction, "新增" + checkTypeName + "合规扫描任务"
	})

	routeAction.GET("/api/v2/containerSec/scap/:checkID/getfile", func(params Params) (string, string) {
		return importAction, "导出扫描结果"
	})

	routeAction.POST("/api/v2/containerSec/scap/v2/:scapType/policy", func(params Params) (string, string) {
		scapType := model.ComplianceCheckType(params.ByName("scapType"))
		scapTypeName := ""
		switch scapType {
		case model.ComplianceCheckTargetTypeKube:
			scapTypeName = "kubernetes"
		case model.ComplianceCheckTargetTypeDocker:
			scapTypeName = "Docker"
		case model.ComplianceCheckTargetTypeHost:
			scapTypeName = "主机"
		}
		return createAction, "新增 " + scapTypeName + " 扫描策略{{.}}"
	})

	routeAction.DELETE("/api/v2/containerSec/scap/v2/:scapType/policy/:id", func(params Params) (string, string) {
		scapType := model.ComplianceCheckType(params.ByName("scapType"))
		scapTypeName := ""
		switch scapType {
		case model.ComplianceCheckTargetTypeKube:
			scapTypeName = "kubernetes"
		case model.ComplianceCheckTargetTypeDocker:
			scapTypeName = "Docker"
		case model.ComplianceCheckTargetTypeHost:
			scapTypeName = "主机"
		}
		return deleteAction, "删除 " + scapTypeName + " 扫描策略{{.}}"
	})

	// 集群安全
	routeAction.POST("/api/v2/platform/hunter/scan", func(params Params) (string, string) {
		return createAction, "新增集群安全扫描任务"
	})

	// 管理中心
	routeAction.POST("/api/v2/platform/data/ttl", func(params Params) (string, string) {
		return editAction, "编辑数据管理"
	})
	routeAction.POST("/api/v2/platform/data/gc", func(params Params) (string, string) {
		return deleteAction, "删除数据"
	})
	routeAction.POST("/api/v2/usercenter/addUser", func(params Params) (string, string) {
		return createAction, "新增用户"
	})
	routeAction.POST("/api/v2/usercenter/editUser", func(params Params) (string, string) {
		return editAction, "编辑用户"
	})
	routeAction.POST("/api/v2/usercenter/resetPassword", func(params Params) (string, string) {
		return editAction, "编辑密码"
	})
	routeAction.POST("/api/v2/usercenter/config/ldap", func(params Params) (string, string) {
		return editAction, "编辑Ldap配置"
	})
	routeAction.POST("/api/v2/usercenter/config/radius", func(params Params) (string, string) {
		return editAction, "编辑radius配置"
	})
	routeAction.POST("/api/v2/usercenter/ldapGroup", func(params Params) (string, string) {
		return editAction, "新增Ldap组{{.}}"
	})
	routeAction.PUT("/api/v2/usercenter/ldapGroup", func(params Params) (string, string) {
		return editAction, "编辑Ldap组{{.}}"
	})
	routeAction.DELETE("/api/v2/usercenter/ldapGroup", func(params Params) (string, string) {
		return editAction, "删除Ldap组{{.}}"
	})
	routeAction.PUT("/api/v2/platform/assets/clusters", func(params Params) (string, string) {
		return editAction, "编辑集群"
	})
	routeAction.PUT("/api/v2/containerSec/ATTCK/conf", func(params Params) (string, string) {
		return uploadAction, "上传离线规则包"
	})
	routeAction.PUT("/api/v1/vulns/updata", func(params Params) (string, string) {
		return uploadAction, "上传漏洞库更新包"
	})
	routeAction.PUT("/api/v2/containerSec/scanner/vulns/updata", func(params Params) (string, string) {
		return uploadAction, "上传漏洞库更新包"
	})

	// 偏移防御
	routeAction.POST("/api/v2/platform/drift/policy/create", func(params Params) (string, string) {
		return createAction, "新增偏移防御策略{{.}}"
	})
	routeAction.POST("/api/v2/platform/drift/policy/update", func(params Params) (string, string) {
		return editAction, "编辑偏移防御策略{{.}}"
	})
	routeAction.POST("/api/v2/platform/drift/policy/delete", func(params Params) (string, string) {
		return deleteAction, "删除偏移防御策略{{.}}"
	})
}

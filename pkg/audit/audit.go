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

	"gitlab.com/piccolo_su/vegeta/cmd/console/service/naviaudit"
	"gitlab.com/security-rd/go-pkg/logging"

	"github.com/go-chi/chi/middleware"
	v7 "github.com/olivere/elastic/v7"
	"github.com/rs/zerolog"
	"gitlab.com/piccolo_su/vegeta/pkg/request"
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
	exportAction  = "导出"
	uploadAction  = "上传"
	processAction = "发起处置"

	editActionEN    = "Edit"
	createActionEN  = "Create"
	deleteActionEN  = "Delete"
	enableActionEN  = "Enable"
	disableActionEN = "Disable"
	eAnddActionEN   = "Enable/Disable"
	importActionEN  = "Import"
	uploadActionEN  = "Upload"
	processActionEN = "Process"
)

var routeAction *Router

type targetResponse struct {
	Target response.TargetRef `json:"target"`
}

type HTTPErrorResponse struct {
	HTTPError response.HTTPError `json:"error"`
}

type Store interface {
	store(ctx context.Context, event *model.NaviAuditEvent) error
}

func RequestLogger(store Store, queue *util.Queue) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			rMap, ok := getVerb(r)
			// verb, detail, ok := getVerb(r)
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
				var status string

				if failedAudit(ww) {
					status = "false"
				} else {
					status = "true"
				}

				verb := rMap["zh"]["verb"]
				detail := rMap["zh"]["detail"].(string)
				detailEN := rMap["en"]["detail"].(string)
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
						data["status"] = status
						detail, _ = generateDetail(detail, objName)
						detailEN, _ = generateDetail(detailEN, objName)
						if status == "false" {
							data["err"] = getObjectErrInfo(respBody)
						}
						if r.URL.Path == "/api/v2/usercenter/login" {
							active := getObjectActive(respBody)
							switch active {
							case "MfaBinding":
								detail = "多因素认证绑定密钥"
								detailEN = "binding mfa secret"
							case "MfaVerify":
								detail = "多因素登录认证"
								detailEN = "verify mfa secret"
							default:

							}
						}

						data["detail"] = detail
					}
				} else {
					target := ww.Header().Get("targetref")
					if target != "" {
						targetRef := response.TargetRef{}
						err := json.Unmarshal([]byte(target), &targetRef)
						if err == nil {
							data["objName"] = targetRef.Name
							data["status"] = targetRef.Status
							detail, _ = generateDetail(detail, targetRef.Name)
							detailEN, _ = generateDetail(detailEN, targetRef.Name)
							data["detail"] = detail
						}
					}
				}

				verbEN := rMap["en"]["verb"]
				data["metaData"] = map[string]interface{}{
					"en": map[string]interface{}{"verb": verbEN, "detail": detailEN, "status": status},
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
			func() {
				service, ok := naviaudit.GetService()
				if !ok {
					return
				}
				data, err := json.Marshal(auditEvt)
				if err != nil {
					logging.Get().Error().Msgf("send log from syslog failed:%v", err)
				}
				err = service.SendLog(data)
				if err != nil {
					logging.Get().Error().Msgf("send log from syslog failed:%v", err)
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

	e.auditEvt.MetaData = make(map[string]interface{})
	verb := extraData["verb"]
	detail := extraData["detail"]
	extraDataStatus := extraData["status"]
	err := extraData["err"]

	metaData, ok := extraData["metaData"].(map[string]interface{})
	if ok {
		for k, v := range metaData {
			e.auditEvt.MetaData[k] = v
		}
	}

	objName, ok := extraData["objName"]
	if ok && objName != nil {
		if e.auditEvt.MetaData == nil {
			e.auditEvt.MetaData = make(map[string]interface{})
		}
		e.auditEvt.MetaData["objName"] = objName
	} else {
		return
	}
	if len(header) > 0 {
		resp.Header = headerLogField(header)
	}

	e.auditEvt.HttpResponse = resp
	e.auditEvt.Verb = verb.(string)
	e.auditEvt.Detail = detail.(string)
	e.auditEvt.Status = extraDataStatus.(string)
	if e.auditEvt.Status == "false" {
		e.auditEvt.Err = err.(string)
	}

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

func getVerb(r *http.Request) (map[string]map[string]interface{}, bool) {
	path := r.URL.Path
	fn, params, _ := routeAction.Lookup(r.Method, path)
	if fn != nil {
		result := fn(params)
		return result, true
	}
	return nil, false
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
	req := &model.HttpRequest{
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

	userName := request.GetAccountFromContext(r.Context())
	user := &model.UserInfo{Name: userName}

	return &model.NaviAuditEvent{
		RequestID:   requestID,
		User:        user,
		HttpRequest: req,
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

func needAudit(w middleware.WrapResponseWriter) bool {
	status := w.Status()
	return status < 400
}

func getObjectName(body []byte) string {
	resp := &targetResponse{}
	err := json.Unmarshal(body, resp)
	if err != nil {
		return ""
	}
	return resp.Target.Name
}

func getObjectActive(body []byte) string {
	resp := &targetResponse{}
	err := json.Unmarshal(body, resp)
	if err != nil {
		return ""
	}
	return resp.Target.Active
}

func getObjectErrInfo(body []byte) string {
	resp := &HTTPErrorResponse{}
	err := json.Unmarshal(body, resp)
	if err != nil {
		return ""
	}
	return resp.HTTPError.Message
}

func failedAudit(w middleware.WrapResponseWriter) bool {
	status := w.Status()
	return status != 200
}
func init() {
	routeAction = newRouter()
	// 平台报告
	routeAction.POST("/api/v2/platform/report/template", func(params Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增平台报告{{.}}"},
			"en": {
				"verb":   createActionEN,
				"detail": "Add platform report{{.}}"},
		}

		// return createAction, "新增平台报告{{.}}"
	})
	routeAction.PUT("/api/v2/platform/report/template", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑平台报告{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit platform report {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/platform/report/template", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除平台报告{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete platform report {{.}}",
			},
		}
	})
	routeAction.GET("/api/v2/platform/report/recordDetail", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   exportAction,
				"detail": "导出平台报告{{.}}",
			},
			"en": {
				"verb":   importActionEN,
				"detail": "Import platform report {{.}}",
			},
		}
	})

	// 主动防御
	routeAction.POST("/api/v2/containerSec/watson/baitService", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑诱捕服务{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit bait service {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/watson/baitService", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增诱捕服务{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add bait service {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/watson/baitService", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除诱捕服务{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete bait service {{.}}",
			},
		}
	})

	// 用户登录
	routeAction.POST("/api/v2/usercenter/login", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   "登录",
				"detail": "登录",
			},
			"en": {
				"verb":   "Login",
				"detail": "Login",
			},
		}
	})

	// 多因素认证登录
	routeAction.POST("/api/v2/usercenter/loginMfaVerify", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   "多因素认证登录",
				"detail": "{{.}}多因素认证登录",
			},
			"en": {
				"verb":   "MfaLogin",
				"detail": "{{.}}MfaLogin",
			},
		}
	})

	// 资产发现
	routeAction.POST("/api/v2/platform/assets/namespace", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑命名空间{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit namespace {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/platform/assets/resource/userData", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑资源{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit resource {{.}}",
			},
		}
		// return editAction, "编辑资源{{.}}"
	})

	// 事件中心
	routeAction.POST("/api/v2/platform/processingCenter/record", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   processAction,
				"detail": "对Pod: {{.}}发起处置",
			},
			"en": {
				"verb":   processActionEN,
				"detail": "Process pod {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/platform/processingCenter/record/action", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   processAction,
				"detail": "对Pod: {{.}}发起处置",
			},
			"en": {
				"verb":   processActionEN,
				"detail": "Process pod {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/platform/eventsCenter/config", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑通知配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit configuration of notification",
			},
		}
	})
	routeAction.POST("/api/v2/platform/eventsCenter/config/syslog", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑Syslog导出",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit Syslog configuration for importing",
			},
		}
	})

	// ATT&CK
	routeAction.POST("/api/v2/containerSec/ATTCK/ruleSwitch", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   eAnddAction,
				"detail": "启/停用检测规则",
			},
			"en": {
				"verb":   eAnddActionEN,
				"detail": "Enable/Disable detecting rules",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/ATTCK/customConfigs/configs/append", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": createAction + "规则{{.}}的自定义条件",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create custom rule {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/ATTCK/customConfigs/configs/edit", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": editAction + "规则{{.}}的自定义条件",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit custom rule {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/ATTCK/customConfigs/config/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": deleteAction + "规则{{.}}的自定义条件",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Edit custom rule {{.}}",
			},
		}
	})

	// 微隔离
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/resourceTag/infras", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑资源配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit configuration of resources",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/resourceTag/gateways", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑资源配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit configuration of resources",
			},
		}
	})

	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/kinds/:kind/resources/:resource/policy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑资源{{.}}的隔离策略",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit policy rule of resource {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/kinds/:kind/resources/:resource/policy/enabling", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   eAnddAction,
				"detail": "启/停用资源{{.}}的隔离策略",
			},
			"en": {
				"verb":   eAnddActionEN,
				"detail": "Enable/Disable policy rule of resource {{.}}",
			},
		}

	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments/:segment/policy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑资源组{{.}}的隔离策略",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit policy rule of resource group {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增资源组{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create new resource group {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments/:segment", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑资源组{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit resource group {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments/:segment", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除资源组{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete resource group {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/namespaces/:namespace/segments/:segment/policy/enabling", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   eAnddAction,
				"detail": "启/停用资源组{{.}}的隔离策略",
			},
			"en": {
				"verb":   eAnddActionEN,
				"detail": "Enable/Disable policy rule of resource group {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/nsgrps", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增命名空间组{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create new namespace group {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/nsgrps/:nsgrp", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑命名空间组{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit namespace group {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/microseg/clusters/:clusterKey/nsgrps/:nsgrp", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除命名空间组{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete namespace group {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/nsgrps/:nsgrp/policy/enabling", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   eAnddAction,
				"detail": "启/停用命名空间组{{.}}的隔离策略",
			},
			"en": {
				"verb":   eAnddActionEN,
				"detail": "Enable/Disable policy rule of namespace group {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/tenants", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增租户{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create new tenant {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/tenants/:tenant", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑租户{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Create tenant {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/microseg/clusters/:clusterKey/tenants/:tenant", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除租户{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete tenant {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/tenants/:tenant/policy/enabling", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   eAnddAction,
				"detail": "启/停用租户{{.}}的隔离策略",
			},
			"en": {
				"verb":   eAnddActionEN,
				"detail": "Enable/Disable policy rule of tenant {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/microseg/clusters/:clusterKey/logicclusters", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增逻辑集群{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create new logic cluster {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/microseg/clusters/:clusterKey/logicclusters/:logiccluster", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑逻辑集群{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit logic cluster {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/microseg/clusters/:clusterKey/logicclusters/:logiccluster", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除逻辑集群{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete logic cluster {{.}}",
			},
		}
	})

	// 镜像安全
	routeAction.POST("/api/v2/containerSec/scanner/scan-config/strategy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增扫描策略{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create new scanning policy {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/scanner/scan-config/strategy/:strategyID", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑扫描策略{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit scanning policy {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/scan-config/strategy/:strategyID", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除扫描策略{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete scanning policy {{.}}",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/imagereject/trustedImages/rsa", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增密钥{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create new secret key {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/scanner/imagereject/trustedImages/rsa/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑密钥{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit secret key {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/imagereject/trustedImages/rsa/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除密钥{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete secret key {{.}}",
			},
		}
	})

	routeAction.PUT("/api/v2/containerSec/scanner/scan-config/config/:scanConfigID", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑扫描配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit configuration of scanning",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/scan-report", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增镜像扫描报告{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create new scanning report {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/scanner/scan-report/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑镜像扫描报告{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit new scanning report {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/scan-report/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除镜像扫描报告{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete new scanning report {{.}}",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/register/registry", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增镜像仓库{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create new image repository {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/scanner/register/registry/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "更新镜像仓库{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit image repository {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/register/registry/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除镜像仓库{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete new image repository {{.}}",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/images/bases", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增基础镜像{{.}}至基础镜像列表",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add base-image {{.}} to base-imgage list",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/images/bases/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除基础镜像{{.}}出基础镜像列表",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete base-image {{.}} from base-imgage list",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/tasks/image", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增镜像扫描任务",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add image scanning task",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/imagereject/whitelist", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增镜像{{.}}至阻断白名单",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add image {{.}} to whitelist",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/imagereject/whitelist/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除镜像{{.}}出阻断白名单",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete image {{.}} from whitelist",
			},
		}
	})

	routeAction.PUT("/api/v2/containerSec/scanner/imagereject/policy/global", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑阻断节点配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit blocking node configuration",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/imagereject/policy/single", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增阻断策略{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add blocking policy {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/scanner/imagereject/policy/single/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑阻断策略{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit blocking policy {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/scanner/imagereject/policy/single/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除阻断策略{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete blocking policy {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/scanner/tasks/:id/status", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑镜像扫描任务",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit task of image scanning",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/ci/policy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增CI策略{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add CI policy {{.}}",
			},
		}
	})

	routeAction.PUT("/api/v2/containerSec/scanner/ci/policy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "新增CI策略{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit CI policy {{.}}",
			},
		}
	})

	routeAction.DELETE("/api/v2/containerSec/scanner/ci/policy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除CI策略{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete CI policy {{.}}",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scanner/ci/whitelists", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增CI白名单{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add CI whitelist {{.}}",
			},
		}
	})

	routeAction.PUT("/api/v2/containerSec/scanner/ci/whitelists", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑CI白名单{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit CI whitelist {{.}}",
			},
		}
	})

	routeAction.DELETE("/api/v2/containerSec/scanner/ci/whitelist", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "编辑CI白名单{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Edit CI whitelist {{.}}",
			},
		}
	})

	routeAction.PUT("/api/v2/containerSec/scanner/ci/webhook", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑CIWebhook{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit CI Webhook {{.}}",
			},
		}
	})

	// 合规检测
	routeAction.POST("/api/v2/containerSec/scap/v2/:scapType/cronjob", func(p Params) map[string]map[string]interface{} {
		scapType := model.ComplianceCheckType(p.ByName("scapType"))
		checkTypeName := ""
		checkTypeNameEN := ""
		switch scapType {
		case model.ComplianceCheckTargetTypeKube:
			checkTypeName = "编排软件"
			checkTypeNameEN = "Orchestration software"
		case model.ComplianceCheckTargetTypeDocker:
			checkTypeName = "Docker"
			checkTypeNameEN = "Docker"
		case model.ComplianceCheckTargetTypeHost:
			checkTypeName = "主机"
			checkTypeNameEN = "Host"
		}

		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": fmt.Sprintf("编辑%s扫描配置", checkTypeName),
			},
			"en": {
				"verb":   editActionEN,
				"detail": fmt.Sprintf("Edit %s scanning configuration", checkTypeNameEN),
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scap/v2/:scapType/job", func(p Params) map[string]map[string]interface{} {
		checkType := model.ComplianceCheckType(p.ByName("scapType"))
		var checkTypeName string
		var checkTypeNameEN string
		switch checkType {
		case model.ComplianceCheckTargetTypeKube:
			checkTypeName = "编排软件"
			checkTypeNameEN = "Orchestration software"
		case model.ComplianceCheckTargetTypeDocker:
			checkTypeName = "Docker"
			checkTypeNameEN = "Docker"
		case model.ComplianceCheckTargetTypeHost:
			checkTypeName = "主机"
			checkTypeNameEN = "Host"
		}
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": fmt.Sprintf("新增%s合规扫描任务", checkTypeName),
			},
			"en": {
				"verb":   createActionEN,
				"detail": fmt.Sprintf("Create %s compliance scanning task", checkTypeNameEN),
			},
		}
	})

	routeAction.GET("/api/v2/containerSec/scap/:checkID/getfile", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   exportAction,
				"detail": "导出扫描结果",
			},
			"en": {
				"verb":   importActionEN,
				"detail": "Import scanning results",
			},
		}
	})

	routeAction.POST("/api/v2/containerSec/scap/v2/:scapType/policy", func(p Params) map[string]map[string]interface{} {
		scapType := model.ComplianceCheckType(p.ByName("scapType"))
		scapTypeName := ""
		scapTypeNameEN := ""
		switch scapType {
		case model.ComplianceCheckTargetTypeKube:
			scapTypeName = "kubernetes"
			scapTypeNameEN = "kubernetes"
		case model.ComplianceCheckTargetTypeDocker:
			scapTypeName = "Docker"
			scapTypeNameEN = "Docker"
		case model.ComplianceCheckTargetTypeHost:
			scapTypeName = "主机"
			scapTypeName = "Host"
		}
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": fmt.Sprintf("新增%s扫描策略{{.}}", scapTypeName),
			},
			"en": {
				"verb":   createActionEN,
				"detail": fmt.Sprintf("Create %s scanning policy {{.}}", scapTypeNameEN),
			},
		}
	})

	routeAction.DELETE("/api/v2/containerSec/scap/v2/:scapType/policy/:id", func(p Params) map[string]map[string]interface{} {
		scapType := model.ComplianceCheckType(p.ByName("scapType"))
		scapTypeName := ""
		scapTypeNameEN := ""
		switch scapType {
		case model.ComplianceCheckTargetTypeKube:
			scapTypeName = "kubernetes"
			scapTypeNameEN = "kubernetes"
		case model.ComplianceCheckTargetTypeDocker:
			scapTypeName = "Docker"
			scapTypeNameEN = "Docker"

		case model.ComplianceCheckTargetTypeHost:
			scapTypeName = "主机"
			scapTypeNameEN = "Host"
		}
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": fmt.Sprintf("新增%s扫描策略{{.}}", scapTypeName),
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": fmt.Sprintf("Delete %s scanning policy {{.}}", scapTypeNameEN),
			},
		}
	})

	// 集群安全
	routeAction.POST("/api/v2/platform/hunter/scan", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增集群安全扫描任务",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add cluster security scan task",
			},
		}
	})

	// 管理中心
	routeAction.POST("/api/v2/platform/data/ttl", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑数据管理",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit data manager",
			},
		}
	})
	routeAction.POST("/api/v2/platform/data/gc", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "删除数据",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Deleted data",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/addUser", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增用户{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add user {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/editUser", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑用户{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit user {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/resetPassword", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑密码",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit password",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/enable", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   eAnddAction,
				"detail": "{{.}}",
			},
			"en": {
				"verb":   eAnddActionEN,
				"detail": "{{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/admin/resetpwd", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "重置{{.}}密码",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Reset password {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/usercenter/delete", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除用户{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Deleted user {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/config/ldap", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑Ldap配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit Ldap configuration",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/config/radius", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑Radius配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit Radius configuration",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/config/idp", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑SSO配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit SSO configuration",
			},
		}
	})
	routeAction.PUT("/api/v2/usercenter/config/login", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑登录配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit login configuration",
			},
		}
	})
	routeAction.POST("/api/v2/usercenter/ldapGroup", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增Ldap组{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add Ldap group {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/usercenter/ldapGroup", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑Ldap组{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit Ldap group {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/usercenter/ldapGroup", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除Ldap组{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete Ldap group {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/platform/assets/clusters", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑集群",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit cluster",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/ATTCK/conf", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   uploadAction,
				"detail": "上传离线规则包",
			},
			"en": {
				"verb":   uploadActionEN,
				"detail": "Upload offline rules package",
			},
		}
	})
	routeAction.PUT("/api/v1/vulns/updata", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   uploadAction,
				"detail": "上传漏洞库更新包",
			},
			"en": {
				"verb":   uploadActionEN,
				"detail": "Upload the update package of the vulnerability package",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/scanner/vulns/updata", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   uploadAction,
				"detail": "上传漏洞库更新包",
			},
			"en": {
				"verb":   uploadActionEN,
				"detail": "Upload the update package of the vulnerability package",
			},
		}
	})
	// 偏移防御
	routeAction.POST("/api/v2/platform/drift/policy/create", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增偏移防御策略{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add drift defense strategy{{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/platform/drift/policy/update", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑偏移防御策略{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit drift defense strategy{{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/platform/drift/policy/delete", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除偏移防御策略{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete drift defense strategy{{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/platform/drift/whitelist", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增偏移防御白名单{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add drift defense whitelist{{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/platform/drift/whitelist/:whitelistID", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑偏移防御白名单{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit drift defense whitelist{{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/platform/drift/whitelist/:whitelistID", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除偏移防御白名单{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete drift defense whitelist{{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/platform/drift/policy/batch/create", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "批量新增偏移防御策略{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Batch create drift defense strategy{{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/platform/drift/policy/batch/update", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "批量编辑偏移防御策略{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Batch edit drift defense strategy{{.}}",
			},
		}
	})

	// 	// 事件中心
	// 	// 白名单
	routeAction.POST("/api/v2/platform/sherlock/palace/whitelist", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增事件中心白名单{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Add event center whitelist{{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/platform/sherlock/palace/whitelist", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "修改事件中心白名单{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit event center whitelist{{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/platform/sherlock/palace/whitelist", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除事件中心白名单{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete event center whitelist{{.}}",
			},
		}
	})
	// 事件标记-单条
	routeAction.POST("/api/v2/platform/sherlock/palace/event/process", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑事件{{.}}的事件标记",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit event tag for event {{.}}",
			},
		}
	})
	// 事件标记-批量
	routeAction.POST("/api/v2/platform/sherlock/palace/event/process/query", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑多条事件标记",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit multiple event tag",
			},
		}
	})

	// 集群管理
	routeAction.PUT("/api/v2/platform/assets/cluster", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "修改集群{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit cluster {{.}}",
			},
		}
	})

	routeAction.DELETE("/api/v2/platform/assets/cluster/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除集群{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete cluster {{.}}",
			},
		}
	})

	// 节点镜像
	// 扫描任务
	routeAction.POST("/api/v2/platform/nodeImage/scanTask/image/scan/task", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增节点镜像扫描任务",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create node image scan task",
			},
		}
	})

	routeAction.PUT("/api/v2/platform/nodeImage/scanTask/image/scan/task/status", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "更新节点镜像扫描任务",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Update node image scan task status",
			},
		}
	})

	routeAction.PUT("/api/v2/platform/nodeImage/scanTask/image/scan/subtask/reschedule", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "更新节点镜像扫描任务",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Update node image scan task status",
			},
		}
	})

	routeAction.PUT("/api/v2/platform/nodeImage/config/scan/image", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "编辑节点镜像配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit node image config",
			},
		}
	})

	routeAction.PUT("/api/v2/platform/nodeImage/security/detect/policy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "更新节点镜像安全策略:{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Update node image security policy {{.}}",
			},
		}
	})

	routeAction.POST("/api/v2/platform/nodeImage/security/detect/policy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增节点镜像安全策略 {{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create node image security policy {{.}}",
			},
		}
	})

	routeAction.DELETE("/api/v2/platform/nodeImage/security/detect/policy", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除节点镜像安全策略 {{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete node image security policy {{.}}",
			},
		}
	})

	// 导出
	routeAction.POST("/api/v2/containerSec/export/task/imageSearch", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "导出镜像报告",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Export the image report",
			},
		}
	})

	// 导出
	routeAction.POST("/api/v2/containerSec/export/task/image", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "导出镜像报告",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Export the image report",
			},
		}
	})

	// 导出
	routeAction.POST("/api/v2/containerSec/export/task/scanTask", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "导出镜像报告",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Export the image report",
			},
		}
	})

	// waf
	routeAction.POST("/api/v2/containerSec/waf/service", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增waf应用{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create waf application {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/waf/service", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "修改waf应用{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit waf application {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/waf/service/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   deleteAction,
				"detail": "删除waf应用{{.}}",
			},
			"en": {
				"verb":   deleteActionEN,
				"detail": "Delete waf application {{.}}",
			},
		}
	})
	routeAction.POST("/api/v2/containerSec/waf/certCrt", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增公钥",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create cert",
			},
		}
	})
	routeAction.POST("/api/v2/containerSec/waf/certKey", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增私钥",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create private key",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/waf/config", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "修改waf配置",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit waf configuration",
			},
		}
	})
	routeAction.POST("/api/v2/containerSec/waf/blackwhitelist", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   createAction,
				"detail": "新增黑白名单{{.}}",
			},
			"en": {
				"verb":   createActionEN,
				"detail": "Create black/white list {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/waf/blackwhitelist", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "修改黑白名单{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit black/white list {{.}}",
			},
		}
	})
	routeAction.DELETE("/api/v2/containerSec/waf/blackwhitelist/:id", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "删除黑白名单{{.}}",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Delete black/white list {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/waf/blackwhitelist/enabling", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   eAnddAction,
				"detail": "启/禁用黑白名单{{.}}",
			},
			"en": {
				"verb":   eAnddActionEN,
				"detail": "Enable/Disable black/white list {{.}}",
			},
		}
	})
	routeAction.PUT("/api/v2/containerSec/waf/rules", func(p Params) map[string]map[string]interface{} {
		return map[string]map[string]interface{}{
			"zh": {
				"verb":   editAction,
				"detail": "修改waf规则",
			},
			"en": {
				"verb":   editActionEN,
				"detail": "Edit waf rules",
			},
		}
	})
}

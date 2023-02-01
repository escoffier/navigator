package mozart

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo" // todo: 去掉依赖
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

func (w *Worker) CacheContext(x rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	sa := a.Value.String()
	v, err := w.getByPath(w.Cache, sa[1:len(sa)-1])
	if err != nil {
		logging.Get().Debug().Err(err).Str("path", sa).Interface("cache", w.Cache).Msg("getByPath fails")
		return ast.NullTerm(), err
	}

	switch tv := v.(type) {
	case string:
		return ast.StringTerm(tv), nil
	case int:
		return ast.IntNumberTerm(tv), nil
	case map[string]interface{}:
		btv, _ := json.Marshal(tv)
		return ast.StringTerm(string(btv)), nil
	case []interface{}:
		btv, _ := json.Marshal(tv)
		return ast.StringTerm(string(btv)), nil
	default:
		logging.Get().Warn().Interface("v", v).Msg(fmt.Sprintf("what is the type of value: %T", v))
	}

	return ast.NullTerm(), nil
}

func (w *Worker) getByPath(m map[string]interface{}, path string) (interface{}, error) {
	keys := strings.Split(path, ".")
	var ok bool
	var v interface{}
	for i := range keys {
		v, ok = m[keys[i]]
		if !ok {
			return nil, errors.New("no such key: " + keys[i])
		}
		if i == len(keys)-1 {
			return v, nil
		} else {
			m, ok = v.(map[string]interface{})
			if !ok {
				return ast.StringTerm(string("")), errors.New("invalid path key: " + keys[i])
			}
		}
	}
	return nil, nil
}

func (w *Worker) ExistsInPeriod(x rego.BuiltinContext, as []*ast.Term) (*ast.Term, error) {
	param, ok := as[0].Value.(ast.String)
	if !ok {
		err := errors.New("a not string")
		logging.Get().Error().Err(err).Interface("a", as[0]).Msg(err.Error())
		return ast.BooleanTerm(false), err
	}
	sParam := param.String()[1 : len(param.String())-1]

	period, ok := as[1].Value.(ast.String)
	if !ok {
		err := errors.New("b not string")
		logging.Get().Error().Err(err).Interface("b", as[1]).Msg(err.Error())
		return ast.BooleanTerm(false), errors.New("b not string")
	}
	sPeriod := period.String()[1 : len(period.String())-1]
	var tPeriod time.Duration
	sNum := sPeriod[:len(sPeriod)-1]
	num, err := strconv.Atoi(sNum)
	if err != nil {
		err := errors.New("sPeriod convert int fails")
		logging.Get().Error().Err(err).Interface("period", period.String()).Msg(err.Error())
		return ast.BooleanTerm(false), err
	}
	switch sPeriod[len(sPeriod)-1] {
	case 's':
		tPeriod = time.Second * time.Duration(num)
	default:
		logging.Get().Error().Err(errors.New("invalid period key")).Str("key", sPeriod).Msg("invalid period key")
		tPeriod = time.Second * time.Duration(num)
	}

	sMozartStartTime := as[2].Value.String()
	mozartStartTime, err := time.Parse(time.RFC3339, sMozartStartTime[1:len(sMozartStartTime)-1])
	if err != nil {
		logging.Get().Error().Err(err).Interface("c", as[2].Value).Msg("invalid mozartStartTime")
		return ast.BooleanTerm(false), err
	}

	now := time.Now()
	tStart := mozartStartTime.Add(-tPeriod)
	tEnd := mozartStartTime.Add(tPeriod)
	if !tEnd.Before(now) {
		delta := tEnd.Sub(time.Now())
		ticker := time.NewTicker(delta)
		<-ticker.C
		ticker.Stop()
	}
	events, exists := checkCache(sParam, tStart, tEnd)
	if exists {
		sTriggerValue := as[3].Value.String()
		sTriggerValue = sTriggerValue[1 : len(sTriggerValue)-1]

		sRelatedPath := as[4].Value.String()
		for i := range events {
			iRelatedValue, err := w.getByPath(events[i], sRelatedPath[1:len(sRelatedPath)-1])
			if err != nil {
				logging.Get().Error().Err(err).Str("related_path", sRelatedPath).Msg("getByPath fails")
				continue
			}
			sRelatedValue, ok := iRelatedValue.(string)
			if !ok {
				continue
			}
			if sTriggerValue == sRelatedValue {
				return ast.BooleanTerm(true), nil
			}
		}
	}
	return ast.BooleanTerm(false), errors.New("no matched cache: " + sParam)
}

func (w *Worker) NotExistsInPeriod(x rego.BuiltinContext, a, b, c *ast.Term) (*ast.Term, error) {
	param, ok := a.Value.(ast.String)
	if !ok {
		err := errors.New("a not string")
		logging.Get().Error().Err(err).Interface("a", a).Msg(err.Error())
		return ast.BooleanTerm(true), err
	}
	sParam := param.String()[1 : len(param.String())-1]

	period, ok := b.Value.(ast.String)
	if !ok {
		err := errors.New("b not string")
		logging.Get().Error().Err(err).Interface("b", b).Msg(err.Error())
		return ast.BooleanTerm(true), errors.New("b not string")
	}
	sPeriod := period.String()[1 : len(period.String())-1]
	var tPeriod time.Duration
	sNum := sPeriod[:len(sPeriod)-1]
	num, err := strconv.Atoi(sNum)
	if err != nil {
		err := errors.New("sPeriod convert int fails")
		logging.Get().Error().Err(err).Interface("period", period.String()).Msg(err.Error())
		return ast.BooleanTerm(true), err
	}
	switch sPeriod[len(sPeriod)-1] {
	case 's':
		tPeriod = time.Second * time.Duration(num)
	default:
		logging.Get().Error().Err(errors.New("invalid period key")).Str("key", sPeriod).Msg("invalid period key")
		tPeriod = time.Second * time.Duration(num)
	}

	sMozartStartTime := c.Value.String()
	mozartStartTime, err := time.Parse(time.RFC3339, sMozartStartTime[1:len(sMozartStartTime)-1])
	if err != nil {
		logging.Get().Error().Err(err).Interface("c", c.Value).Msg("invalid mozartStartTime")
		return ast.BooleanTerm(false), err
	}

	now := time.Now()
	tStart := mozartStartTime.Add(-tPeriod)
	tEnd := mozartStartTime.Add(tPeriod)
	if !tEnd.Before(now) {
		delta := tEnd.Sub(time.Now())
		ticker := time.NewTicker(delta)
		<-ticker.C
		ticker.Stop()
	}
	_, exists := checkCache(sParam, tStart, tEnd)
	if exists {
		return ast.BooleanTerm(false), nil
	}
	return ast.BooleanTerm(true), nil

}

func (w *Worker) GenerateAlertSignal(x rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {

	tPayload := a.Value.String()
	tPayload = tPayload[1 : len(tPayload)-1]
	tPayload = strings.ReplaceAll(tPayload, "\\\\", "\\")
	tPayload = strings.ReplaceAll(tPayload, "\\\"", "\"")
	tSignal := SignalPayload{}
	err := json.Unmarshal([]byte(tPayload), &tSignal)

	if err != nil {
		return nil, err
	}

	m := make(map[string]string)
	err = json.Unmarshal([]byte(b.Value.String()), &m)
	if err != nil {
		return nil, err
	}

	rule, ok := m["rule"]
	if !ok {
		return nil, errors.New("invalid params, missing rule")
	}
	delete(m, "rule")
	delete(m, "priority")

	for k, v := range m {
		triggerValue, e := getInfoFromOutput(fmt.Sprintf("%s=", k), tSignal.Output)
		if e != nil {
			continue
		}
		tSignal.Output = strings.Replace(tSignal.Output, triggerValue, v, -1)
	}

	alertSignal := SignalPayload{
		Version1:     tSignal.Version1,
		ClusterKey:   tSignal.ClusterKey,
		Hostname:     tSignal.Hostname,
		NodeName:     tSignal.NodeName,
		Output:       tSignal.Output,
		Priority:     -1,
		Rule:         rule,
		Source:       tSignal.Source,
		Tags:         tSignal.Tags,
		Time:         tSignal.Time,
		OutputFields: tSignal.OutputFields,
		OutputMap:    tSignal.OutputMap,
	}

	bas, err := json.Marshal(alertSignal)
	if err != nil {
		return nil, err
	}

	return ast.StringTerm(string(bas)), nil
}

func (w *Worker) SendSignalToPalace(x rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {

	sSignal := a.Value.String()
	sSignal = sSignal[1 : len(sSignal)-1]
	// todo: 这里很恶心，咋处理
	sSignal = strings.ReplaceAll(sSignal, "\\\\", "\\")
	sSignal = strings.ReplaceAll(sSignal, "\\\"", "\"")
	signal := SignalPayload{}
	err := json.Unmarshal([]byte(sSignal), &signal)
	if err != nil {
		logging.Get().Error().Err(err).Str("signal", sSignal).Msg("signal unmarshal error")
		return ast.NullTerm(), err
	}

	ruleCategory := "ATT&CK"
	for _, tag := range signal.Tags {
		if tag == "Watson" || tag == "ATT&CK" {
			ruleCategory = tag
			break
		}
	}

	ruleKey := palace.RuleKey{
		Version1: signal.Version1,
		Category: ruleCategory,
		Name:     signal.Rule,
	}

	clusterName, ok := w.deps.cm.ClusterName()
	if !ok || clusterName == "" {
		clusterName = signal.ClusterKey
	}

	signalContext, podUID, podName, namespace := generateSignalContext(&signal)
	containerID, _ := signalContext["container_id"].(string)
	containerName, _ := signalContext["container.name"].(string)
	if containerName == "" {
		containerName, ok = signal.OutputMap["container_name"]
		if !ok || containerName == "<NA>" {
			containerName = containerID
		}
	}

	// 所有告警均存在 cluster + hostname
	scopes := []palace.Scope{
		{
			Kind: palace.ScopeKindCluster,
			ID:   signal.ClusterKey,
			Name: clusterName, // cluster name
		},
		{
			Kind: palace.ScopeKindHostname,
			Name: signal.Hostname,
		},
	}

	if namespace != "" {
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindNamespace,
			Name: namespace,
		})
	}

	ownerRes, _, exist := w.getOwnerInfo(podName, namespace)
	if exist {
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindResource,
			Name: fmt.Sprintf("%s(%s)", ownerRes.Name, ownerRes.Kind),
		})
	}

	if podName != "" {
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindPod,
			ID:   podUID,
			Name: podName,
		})
	}

	// 明确不是主机告警，追加 container
	if containerID != "host" && containerName != "" {
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindContainer,
			ID:   containerID,   // container id
			Name: containerName, // container name
		})
	}

	err = w.deps.palace.SendSignal(ruleKey, scopes, signalContext)
	return ast.NullTerm(), err
}

func (w *Worker) getOwnerInfo(podName, namespace string) (*nodeinfo.Resource, string, bool) {

	res, exist := w.deps.prInfo.GetPod(namespace, podName)
	if exist && res != nil {
		return res, namespace, true
	}
	return nil, "", false
}

func checkCache(sParam string, tStart, tEnd time.Time) ([]map[string]interface{}, bool) {
	Cache.Lock.Lock()
	items, ok := Cache.Data[sParam]
	Cache.Lock.Unlock()
	events := make([]map[string]interface{}, 0)
	if ok {
		for i := range items {
			eventTime, ok := items[i]["time"].(time.Time)
			if !ok {
				logging.Get().Error().Err(errors.New("ridiculous, no time in event")).Interface("event", items[i]).Msg("ridiculous, no time in event")
				continue
			}
			if eventTime.Before(tEnd) && eventTime.After(tStart) {
				events = append(events, items[i])
			}
		}
		if len(events) != 0 {
			return events, true
		}
	}

	return events, false
}

func generateSignalContext(data *SignalPayload) (signalContext map[string]interface{}, podUID, podName, namespace string) {

	filteredOutFields := []string{
		model.FieldK8sNsName,
		model.FieldK8sPodName,
		model.FieldPodUID,
		model.FieldEvtTime,
		"k8s_ns_name",
		"k8s_pod_name",
		"k8s_pod_id",
		"evt_time",
		"zh_msg",
		"rule_type",
	}

	signalContext = map[string]interface{}{}

	ppid := data.OutputMap["proc_ppid"]

	procPname, ok := data.OutputMap["proc_pname"]
	if ok && len(ppid) > 0 {
		signalContext["proc.pname"] = procPname + fmt.Sprintf("(%s)", ppid)
		delete(data.OutputMap, model.FieldParentProcessName)
		delete(data.OutputMap, "proc_pname")
	}

	command := data.OutputMap["proc_cmdline"]

	pid := data.OutputMap["proc_pid"]
	if command != "" && pid != "" {
		signalContext["proc.name"] = strings.Split(command, " ")[0] + fmt.Sprintf("(%s)", pid)
		delete(data.OutputMap, model.FieldProcessName)
		delete(data.OutputMap, "proc_name")
	}

	if podName = data.OutputFields.K8sPodName; podName == "<NA>" {
		podName = ""
	}
	if namespace = data.OutputFields.K8sNsName; namespace == "<NA>" {
		namespace = ""
	}
	podUID = data.OutputFields.K8sPodID

	for key, value := range data.OutputMap {
		if value == "<NA>" {
			value = ""
		}

		if util.ContainsString(filteredOutFields, key) || strings.HasPrefix(key, "output_origin_") {
			continue
		}

		signalContext[key] = value

		if value == "" {
			switch key {
			case model.FieldProcessPid:
			case "proc_pid":
				if pid != "" {
					signalContext["proc_pid"] = pid
				}
			case model.FieldParentProcessPid:
			case "proc_ppid":
				if ppid != "" {
					signalContext["proc_ppid"] = ppid
				}
			case model.FieldCmdline:
			case "proc_cmdline":
				if len(command) > 0 {
					signalContext["proc_cmdline"] = command
				}
			case "user":
				user := data.OutputMap["user"]
				if len(user) > 0 {
					signalContext["user"] = user
				}
			case model.FieldSyscallType:
			case "syscall_type":
				syscall := data.OutputMap["syscall_name"]
				if len(syscall) > 0 {
					signalContext["syscall_type"] = syscall
				}
			}
		}
	}

	return signalContext, podUID, podName, namespace
}

func getInfoFromOutput(key, output string) (string, error) {
	ErrKeyNotFound := errors.New("key not found")
	if key == "" || output == "" {
		return "", ErrKeyNotFound
	}
	retStr := ""
	resultList := strings.Split(output, key)
	if len(resultList) < 2 {
		return "", ErrKeyNotFound
	}
	retStr = resultList[1]
	resultList = strings.Split(retStr, ",")
	retStr = resultList[0]
	resultList = strings.Split(retStr, ")")
	retStr = resultList[0]
	resultList = strings.Split(retStr, " ")
	retStr = resultList[0]
	return retStr, nil
}

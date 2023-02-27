package mozart

import (
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm/utils"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	json "github.com/json-iterator/go"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo" // todo: 去掉依赖
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

const (
	mozartPathPrefix = "$MOZART_PATH_PREFIX$"
)

func CacheContext(x rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
	Cache.Lock.Lock()
	defer Cache.Lock.Unlock()
	sa := a.Value.String()
	sb := b.Value.String()
	sb = sb[1 : len(sb)-1]
	v, err := getByPath(Cache.Sessions[sb], sa[1:len(sa)-1])
	if err != nil {
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

func getByPath(m map[string]interface{}, path string) (interface{}, error) {
	var v interface{}
	// 这里是对同一个map的成功get做的"缓存"
	if v, ok := m[mozartPathPrefix+path]; ok {
		return v, nil
	}
	// 下面的迭代中对m进行了修改，所以复制一个om（old m），相同的引用
	om := m
	keys := strings.Split(path, ".")
	var ok bool
	for i := range keys {
		v, ok = m[keys[i]]
		if !ok {
			return nil, errors.New("no such key: " + keys[i])
		}
		if i == len(keys)-1 {
			om[mozartPathPrefix+path] = v
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

func (e *Engine) ExistsInPeriod(x rego.BuiltinContext, as []*ast.Term) (*ast.Term, error) {
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

	// 此处为了避免当处理触发信号时，关联信号因各种原因导致后到，所以等待一个关联窗口
	// 未来可以进行pipeline粒度的重跑，或者理解为延后重新执行。但还不知道哪种方式对性能影响更小，先暂时按等待处理。
	now := time.Now()
	tStart := mozartStartTime.Add(-tPeriod)
	tEnd := now.Add(tPeriod)
	ticker := time.NewTicker(tPeriod)
	<-ticker.C
	ticker.Stop()

	sTriggerValue := as[3].Value.String()
	sTriggerValue = sTriggerValue[1 : len(sTriggerValue)-1]

	sRelatedPath := as[4].Value.String()
	check := func(m map[string]interface{}) bool {
		iRelatedValue, err := getByPath(m, sRelatedPath[1:len(sRelatedPath)-1])
		if err != nil {
			return false
		}
		sRelatedValue, ok := iRelatedValue.(string)
		if !ok {
			return false
		}
		return sTriggerValue == sRelatedValue
	}

	_, exists := checkCache(sParam, tStart, tEnd, check)
	if exists {
		return ast.BooleanTerm(true), nil
	}
	return ast.BooleanTerm(false), errors.New("no matched cache: " + sParam)
}

func (e *Engine) NotExistsInPeriod(x rego.BuiltinContext, a, b, c *ast.Term) (*ast.Term, error) {
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
	_, exists := checkCache(sParam, tStart, tEnd, defaultCheckTrue)
	if exists {
		return ast.BooleanTerm(false), nil
	}
	return ast.BooleanTerm(true), nil

}

func (e *Engine) RuleRecentCount(x rego.BuiltinContext, as []*ast.Term) (*ast.Term, error) {

	paramA, ok := as[0].Value.(ast.String)
	if !ok {
		err := errors.New("RuleRecentCount a not string")
		logging.Get().Error().Err(err).Interface("a", as[0]).Msg(err.Error())
		return ast.BooleanTerm(false), err
	}
	ruleName := paramA.String()[1 : len(paramA.String())-1]

	paramB, ok := as[1].Value.(ast.String)
	if !ok {
		err := errors.New("RuleRecentCount b not string")
		logging.Get().Error().Err(err).Interface("b", as[1]).Msg(err.Error())
		return ast.BooleanTerm(false), errors.New("b not string")
	}
	sPeriod := paramB.String()[1 : len(paramB.String())-1]
	tPeriod, err := sDurationToTimeDuration(sPeriod)
	if err != nil {
		return ast.BooleanTerm(false), err
	}

	sTrigger := as[2].Value.String()
	triggerM := make(map[string]interface{})
	sTrigger = sTrigger[1 : len(sTrigger)-1]
	sTrigger = strings.ReplaceAll(sTrigger, "\\\\", "\\")
	sTrigger = strings.ReplaceAll(sTrigger, "\\\"", "\"")
	err = json.Unmarshal([]byte(sTrigger), &triggerM)
	if err != nil {
		logging.Get().Error().Err(err).Interface("cache trigger", as[2].Value).Msg("invalid cache trigger")
		return ast.BooleanTerm(false), err
	}

	sMozartStartTime := as[3].Value.String()
	mozartStartTime, err := time.Parse(time.RFC3339Nano, sMozartStartTime[1:len(sMozartStartTime)-1])
	if err != nil {
		logging.Get().Error().Err(err).Interface("c", as[3].Value).Msg("invalid mozartStartTime")
		return ast.BooleanTerm(false), err
	}

	sThreshold := as[4].Value.String()
	threshold, err := strconv.Atoi(sThreshold)
	if err != nil {
		err := errors.New("sThreshold convert int fails")
		logging.Get().Error().Err(err).Interface("threshold", sThreshold).Msg(err.Error())
		return ast.BooleanTerm(false), err
	}

	sSameFields := as[5].Value.String()
	sSameFields = sSameFields[1 : len(sSameFields)-1]
	sSameFields = strings.ReplaceAll(sSameFields, `\"`, `"`)
	sameFields := make([]string, 0)
	err = json.Unmarshal([]byte(sSameFields), &sameFields)
	if err != nil {
		logging.Get().Error().Err(err).Interface("d", as[5].Value).Msg("invalid sameFields")
		return ast.BooleanTerm(false), err
	}

	sDiffFields := as[6].Value.String()
	sDiffFields = sDiffFields[1 : len(sDiffFields)-1]
	sDiffFields = strings.ReplaceAll(sDiffFields, `\"`, `"`)
	diffFields := make([]string, 0)
	err = json.Unmarshal([]byte(sDiffFields), &diffFields)
	if err != nil {
		logging.Get().Error().Err(err).Interface("e", as[6].Value).Msg("invalid diffFields")
		return ast.BooleanTerm(false), err
	}

	tStart := mozartStartTime.Add(-tPeriod)
	tEnd := mozartStartTime.Add(time.Second)
	valueMap := make(map[string]interface{})
	fields := append(sameFields, diffFields...)
	cacheHashes := make([]string, 0)
	for j := range fields {
		iValue, err := getByPath(triggerM, "payload.output_map."+fields[j])
		if err != nil {
			continue
		}
		if iValue == "<NA>" {
			return ast.BooleanTerm(false), nil
		}
		valueMap[fields[j]] = iValue
		if utils.Contains(sameFields, fields[j]) {
			cacheHashes = append(cacheHashes, fmt.Sprintf("%s:%v", fields[j], iValue))
		}
	}
	check := func(m map[string]interface{}) bool {
		checkValueOk := true
		for j := range sameFields {
			iValue, err := getByPath(m, "payload.output_map."+sameFields[j])
			if err != nil {
				checkValueOk = false
				break
			}
			if valueMap[sameFields[j]] != iValue || iValue == "<NA>" {
				logging.Get().Debug().Str("related_path", sameFields[j]).Interface("trigger value", valueMap[sameFields[j]]).Interface("related value", iValue).Msg("same value not same")
				checkValueOk = false
				break
			}
		}
		if !checkValueOk {
			return false
		}
		for j := range diffFields {
			iValue, err := getByPath(m, "payload.output_map."+diffFields[j])
			if err != nil {
				checkValueOk = false
				break
			}
			if valueMap[diffFields[j]] == iValue || iValue == "<NA>" {
				logging.Get().Debug().Str("related_path", diffFields[j]).Interface("trigger value", valueMap[diffFields[j]]).Interface("related value", iValue).Msg("diff value same")
				checkValueOk = false
				break
			}
		}
		return checkValueOk
	}
	events, exists := checkCache(ruleName, tStart, tEnd, check)

	count := 0
	if len(diffFields) != 0 { // 当前event自身，因为字段全相同，无法被计数，默认为1
		count = 1
	}
	if exists && len(sameFields) != 0 {
		count += len(events)
	}

	if count < threshold {
		return ast.BooleanTerm(false), nil
	}

	ctx := context.Background()
	result, err := e.deps.redis.Get(ctx, recentCountCacheKey(ruleName, sameFields, diffFields, cacheHashes)).Result()
	if err != nil && err != redis.Nil {
		return ast.BooleanTerm(false), nil
	}
	if result != "" || err != redis.Nil {
		logging.Get().Info().Err(err).Str("key", recentCountCacheKey(ruleName, sameFields, diffFields, cacheHashes)).Msg("redis cache already")
		return ast.BooleanTerm(false), nil
	}

	param5, ok := as[7].Value.(ast.String)
	if !ok {
		err := errors.New("RuleRecentCount f not string")
		logging.Get().Error().Err(err).Interface("f", as[7]).Msg(err.Error())
		return ast.BooleanTerm(false), errors.New("f not string")
	}
	sCachePeriod := param5.String()[1 : len(param5.String())-1]
	tCachePeriod, err := sDurationToTimeDuration(sCachePeriod)
	if err != nil {
		return ast.BooleanTerm(false), err
	}

	// setnx 避免并发时的重复触发
	setResult, err := e.deps.redis.SetNX(ctx, recentCountCacheKey(ruleName, sameFields, diffFields, cacheHashes), true, tCachePeriod).Result()
	if err != nil {
		logging.Get().Error().Err(err).Str("key", recentCountCacheKey(ruleName, sameFields, diffFields, cacheHashes)).Msg("redis set error")
		return ast.BooleanTerm(false), nil
	}

	return ast.BooleanTerm(setResult), nil
}

func recentCountCacheKey(ruleName string, sameFields, diffFields, cacheHashes []string) string {
	return strings.Join(append([]string{ruleName}, append(sameFields, append(diffFields, cacheHashes...)...)...), "$")
}

func (e *Engine) GenerateAlertSignal(x rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {

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

func (e *Engine) SendSignalToPalace(x rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {

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

	clusterName, ok := e.deps.cm.ClusterName()
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

	ownerRes, _, exist := e.getOwnerInfo(podName, namespace)
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

		if namespace != "" || podName != "" {
			// in k8s
			scopes = append(scopes, palace.Scope{
				Kind: palace.ScopeKindScene,
				ID:   palace.ScopeIDSceneK8s,
				Name: palace.ScopeNameSceneK8s,
			})
		} else {
			// in not k8s
			scopes = append(scopes, palace.Scope{
				Kind: palace.ScopeKindScene,
				ID:   palace.ScopeIDSceneNk8s,
				Name: palace.ScopeNameSceneNk8s,
			})
		}
	} else {
		// in node
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindScene,
			ID:   palace.ScopeIDSceneHost,
			Name: palace.ScopeNameSceneHost,
		})
	}

	err = e.deps.palace.SendSignal(ruleKey, scopes, signalContext)
	logging.Get().Info().Err(err).Str("rule", ruleKey.Name).Msg("send signal to palace")
	return ast.NullTerm(), err
}

func (e *Engine) getOwnerInfo(podName, namespace string) (*nodeinfo.Resource, string, bool) {

	res, exist := e.deps.prInfo.GetPod(namespace, podName)
	if exist && res != nil {
		return res, namespace, true
	}
	return nil, "", false
}

// 需要注意check函数的实现，内部参数是否会有多协程并发的数据冲突问题
func checkCache(sParam string, tStart, tEnd time.Time, check func(map[string]interface{}) bool) ([]map[string]interface{}, bool) {
	Cache.Lock.Lock()
	items, ok := Cache.Data[sParam]
	defer Cache.Lock.Unlock()
	events := make([]map[string]interface{}, 0)
	if ok {
		// event.time倒序查看，先判断时间段，再判断check
		for i := len(items) - 1; i >= 0; i-- {
			eventTime, ok := items[i]["time"].(time.Time)
			if !ok {
				logging.Get().Error().Err(errors.New("ridiculous, no time in event")).Interface("event", items[i]).Msg("ridiculous, no time in event")
				continue
			}
			if eventTime.After(tEnd) {
				continue
			}
			if eventTime.Before(tStart) {
				break
			}
			if check(items[i]) {
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
	if ok {
		signalContext["proc.pname"] = procPname
		delete(data.OutputMap, model.FieldParentProcessName)
		delete(data.OutputMap, "proc_pname")
	}

	command := data.OutputMap["proc_cmdline"]

	pid := data.OutputMap["proc_pid"]
	if command != "" {
		signalContext["proc.name"] = strings.Split(command, " ")[0]
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

func defaultCheckTrue(m map[string]interface{}) bool { return true }

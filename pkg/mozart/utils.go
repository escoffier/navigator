package mozart

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	gpModel "gitlab.com/security-rd/go-pkg/model"
	gpMozart "gitlab.com/security-rd/go-pkg/mozart"
)

func ConvertOutput2OutputMap(output string, outputFields map[string]interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	quoteStart := strings.Index(output, "(")
	quoteCount := 0
	quoteEnd := strings.LastIndex(output, ")")
	for i := quoteStart + 1; i < len(output); i++ {
		if output[i] == '(' {
			quoteCount += 1
			continue
		}
		if output[i] == ')' {
			if quoteCount == 0 {
				quoteEnd = i
				break
			} else {
				quoteCount -= 1
			}
		}
	}
	if quoteCount != 0 || quoteCount == len(output) {
		return m
	}
	if quoteStart == -1 || quoteEnd == -1 || quoteStart+1 >= quoteEnd {
		return m
	}
	timeEnd := strings.LastIndex(output[:quoteStart], ":")
	if timeEnd != -1 && timeEnd+2 < quoteStart {
		m["output_origin_time"] = output[14:timeEnd]
		m["output_origin_rule"] = output[timeEnd+2 : quoteStart-1]
	}

	dataS := output[quoteStart+1 : quoteEnd]
	data := strings.Split(dataS, ",")
	lastKey := ""
	stack := make([]string, 0)
	for i := range data {
		equalIndex := strings.Index(data[i], "=")
		if equalIndex == -1 {
			stack = append(stack, ","+data[i])
			continue
		}
		kv := []string{data[i][:equalIndex], data[i][equalIndex+1:]}
		needContinue := false
		for j := range kv[0] {
			if !((kv[0][j] >= 48 && kv[0][j] <= 57) || (kv[0][j] >= 65 && kv[0][j] <= 90) || (kv[0][j] >= 97 && kv[0][j] <= 122)) &&
				(kv[0][j] != '_' && kv[0][j] != '-' && kv[0][j] != '.') {
				for k := range stack {
					m[lastKey] = m[lastKey].(string) + stack[k]
				}
				m[lastKey] = m[lastKey].(string) + data[i]
				stack = make([]string, 0)
				needContinue = true
				break
			}
		}
		if needContinue {
			continue
		}
		if len(stack) != 0 {
			value := ""
			for k := range stack {
				value = value + stack[k]
			}
			stack = make([]string, 0)
			m[lastKey] = m[lastKey].(string) + value
		}

		m[kv[0]] = kv[1]
		lastKey = kv[0]
	}

	m = ConvertKeyDotToUnderScore(m)
	for k, v := range outputFields {
		m[k] = v
	}

	return m
}

func sha256Hash(bs []byte) string {
	m := sha256.New()
	m.Write(bs)
	sbs := m.Sum(nil)
	return fmt.Sprintf("%x", sbs)
}

// input: 1s, 2m, 3h
func sDurationToTimeDuration(sd string) (time.Duration, error) {
	var t time.Duration
	sCacheNum := sd[:len(sd)-1]
	cacheNum, err := strconv.Atoi(sCacheNum)
	if err != nil {
		err := errors.New("sd convert int fails")
		logging.Get().Error().Err(err).Interface("sDuration", sd).Msg(err.Error())
		return t, err
	}
	switch sd[len(sd)-1] {
	case 's':
		t = time.Second * time.Duration(cacheNum)
	case 'm':
		t = time.Minute * time.Duration(cacheNum)
	case 'h':
		t = time.Hour * time.Duration(cacheNum)
	default:
		err = errors.New("invalid duration key")
		logging.Get().Error().Err(err).Str("sDuration", sd).Msg("invalid duration key")
		return t, err
	}
	return t, nil
}

func ConvertKeyDotToUnderScore(m map[string]interface{}) map[string]interface{} {
	nm := make(map[string]interface{}, len(m))
	for k, v := range m {
		nk := strings.ReplaceAll(k, ".", "_")
		if mv, ok := v.(map[string]interface{}); ok { // 暂未考虑其他的map类型
			v = ConvertKeyDotToUnderScore(mv)
		}
		nm[nk] = v
	}
	return nm
}

func convertSpaceToUnderScore(s string) string {
	return strings.ReplaceAll(s, " ", "_")
}

// UserRule2Falco user规则转换成falco规则，并输出falco和mozart的对应关系
// 因为mozart可能存在相同的condition，所以falco和mozart为一对多的关系
func UserRule2Falco(origin []byte) ([]byte, map[string][]string, error) {
	var userRules []gpModel.UserRuleYaml
	err := yaml.Unmarshal(origin, &userRules)
	if err != nil {
		return nil, nil, err
	}

	type FalcoWithIndex struct {
		falco model.FalcoYaml
		index int
	}

	falcoMacros := make([]model.FalcoYaml, 0)
	falcoRules := make([]model.FalcoYaml, 0)
	falcoRulesWithIndex := make([]FalcoWithIndex, 0)
	falcoRulesMap := make(map[string]FalcoWithIndex)
	conditionCache := make(map[string]conditionCacheItem)
	conditionMozartMap := make(map[string][]string)

	userRuleKeyMap := make(map[string]struct{})
	for i := range userRules {
		for j := range userRules[i].MozartYamls {
			// 自定义规则会修改用户规则的condition，此处覆盖到mozart规则上
			// 只有key相同，才说明来源于同一个mozart rule，condition才可以替换
			if userRules[i].MozartYamls[j].Key == userRules[i].Key {
				userRules[i].MozartYamls[j].Condition = userRules[i].Condition
			}

			if _, ok := userRuleKeyMap[userRules[i].MozartYamls[j].Key]; ok {
				continue
			} else {
				userRuleKeyMap[userRules[i].MozartYamls[j].Key] = struct{}{}
			}

			var falcoRule model.FalcoYaml
			var ok bool
			if gpMozart.IsMozartRule(userRules[i].MozartYamls[j]) {
				falcoRule, ok, err = mozartRule2FalcoRule(userRules[i].MozartYamls[j], conditionCache)
				if err != nil {
					logging.Get().Error().Err(err).Interface("mozartRule", userRules[i]).Msg("mozartRule2FalcoRule fails")
					continue
				}
				if ok {
					if _, ok := conditionMozartMap[falcoRule.Condition]; ok {
						conditionMozartMap[falcoRule.Condition] = append(conditionMozartMap[falcoRule.Condition], userRules[i].Key)
					} else {
						conditionMozartMap[falcoRule.Condition] = []string{userRules[i].Key}
					}

					if fwi, ok := falcoRulesMap[falcoRule.Condition]; ok {
						fwi.falco = falcoRule
						falcoRulesMap[falcoRule.Condition] = fwi
					} else {
						falcoRulesMap[falcoRule.Condition] = FalcoWithIndex{falcoRule, i*100 + j}
					}
				}
			}
			if gpMozart.IsMozartRelatedRule(userRules[i].MozartYamls[j]) {
				falcoRule, ok, err = mozartRelatedRule2FalcoRule(userRules[i].MozartYamls[j], conditionCache)
				if err != nil {
					logging.Get().Error().Err(err).Interface("mozartRule", userRules[i]).Msg("mozartRelatedRule2FalcoRule fails")
					continue
				}
				if ok {
					if _, ok := conditionMozartMap[falcoRule.Condition]; ok {
						conditionMozartMap[falcoRule.Condition] = append(conditionMozartMap[falcoRule.Condition], userRules[i].Key)
					} else {
						conditionMozartMap[falcoRule.Condition] = []string{userRules[i].Key}
					}

					if fwi, ok := falcoRulesMap[falcoRule.Condition]; ok {
						fwi.falco = falcoRule
						falcoRulesMap[falcoRule.Condition] = fwi
					} else {
						falcoRulesMap[falcoRule.Condition] = FalcoWithIndex{falcoRule, i*100 + j}
					}
				}
			}

		}
		if gpMozart.IsURMozartMarco(userRules[i]) {
			continue
		}
		if gpMozart.IsURMarco(userRules[i]) {
			falcoRule, ok, err := marco2Falco(userRules[i])
			if err != nil {
				logging.Get().Error().Err(err).Interface("mozartRule", userRules[i]).Msg("marco2Falco fails")
				continue
			}
			if ok {
				falcoMacros = append(falcoMacros, falcoRule)
			}
		}
	}

	falcoMozartMap := make(map[string][]string)
	for k, v := range conditionMozartMap {
		if falcoRule, ok := falcoRulesMap[k]; !ok {
			continue
		} else {
			falcoMozartMap[falcoRule.falco.Rule] = v
		}
	}

	for _, v := range falcoRulesMap {
		falcoRulesWithIndex = append(falcoRulesWithIndex, v)
	}
	sort.Slice(falcoRulesWithIndex, func(i, j int) bool {
		return falcoRulesWithIndex[i].index < falcoRulesWithIndex[j].index
	})

	for i := range falcoRulesWithIndex {
		falcoRules = append(falcoRules, falcoRulesWithIndex[i].falco)
	}
	for i := range falcoMacros {
		falcoRules = append(falcoRules, falcoMacros[i])
	}

	bfr, err := yaml.Marshal(falcoRules)
	if err != nil {
		logging.Get().Error().Err(err).Msg("falcoRules marshal fails")
	}
	return bfr, falcoMozartMap, err
}

type conditionCacheItem struct {
	ruleName string
	output   string
}

func mozartRule2FalcoRule(my gpModel.MozartYaml, conditionCache map[string]conditionCacheItem) (model.FalcoYaml, bool, error) {
	ruleName := my.Key
	output := my.Output
	item, sameCondition := conditionCache[my.Condition]
	if sameCondition {
		ruleName = item.ruleName + " - " + my.Key
		output = unionOutput(item.output, output)
	}
	conditionCache[my.Condition] = conditionCacheItem{
		ruleName: ruleName,
		output:   output,
	}
	return model.FalcoYaml{
		Rule:      ruleName,
		Condition: my.Condition,
		Desc:      ruleName,
		Output:    output,
		Priority:  "ALERT",
		Tags:      my.Info.Tags,
	}, true, nil
}

func unionOutput(output1, output2 string) string {
	output1s := strings.Split(output1, ",")
	output2s := strings.Split(output2, ",")
	outputMap := make(map[string]string)
	outputs := append(output1s, output2s...)
	for i := range outputs {
		kv := strings.Split(outputs[i], "=")
		if len(kv) != 2 {
			continue
		}
		outputMap[kv[0]] = strings.TrimSuffix(kv[1], "\n")
	}
	output := ""
	for k, v := range outputMap {
		output += "," + k + "=" + v
	}
	if len(output) != 0 {
		output = output[1:]
	}
	return output
}

func mozartRelatedRule2FalcoRule(my gpModel.MozartYaml, conditionCache map[string]conditionCacheItem) (model.FalcoYaml, bool, error) {
	return mozartRule2FalcoRule(my, conditionCache)
}

func marco2Falco(ury gpModel.UserRuleYaml) (model.FalcoYaml, bool, error) {
	if ury.Macro != "" {
		return model.FalcoYaml{
			Macro:     ury.Macro,
			Condition: ury.Condition,
		}, true, nil
	}
	return model.FalcoYaml{
		List:  ury.List,
		Items: ury.Items,
	}, true, nil
}

func genEventScopeHash(payload SignalPayload) string {
	value := ""
	// cluster
	value += payload.ClusterKey + "$"
	// hostname
	value += payload.Hostname + "$"
	// namespace
	namespace := ""
	if namespace = payload.OutputFields["k8s_ns_name"]; namespace == "<NA>" || namespace == "null" {
		namespace = ""
	}
	value += namespace + "$"
	// pod
	podUID := ""
	if podUID = payload.OutputFields["k8s_pod_id"]; podUID == "<NA>" || podUID == "null" {
		podUID = ""
	}
	value += podUID + "$"
	// container
	containerID := ""
	if containerID = payload.OutputFields["container_id"]; containerID == "<NA>" || containerID == "null" {
		containerID = ""
	}
	value += containerID + "$"

	return value
}

func getEventCmdline(payload SignalPayload) string {
	cmdline, _ := payload.OutputFields["proc_cmdline"]
	return cmdline
}

type requestMozart struct {
	name    string
	scope   string
	cmdline string
	time    time.Time
}

type requestCache struct {
	cache map[string]requestMozart
	lock  sync.Mutex
}

var RequestCache requestCache

func (cache *requestCache) init() {
	RequestCache = requestCache{
		cache: make(map[string]requestMozart),
		lock:  sync.Mutex{},
	}
}

func (cache *requestCache) get(name string) (requestMozart, bool) {
	cache.lock.Lock()
	defer cache.lock.Unlock()
	if req, ok := cache.cache[name]; ok {
		return req, true
	}
	return requestMozart{}, false
}

func (cache *requestCache) set(name string, req requestMozart) {
	cache.lock.Lock()
	defer cache.lock.Unlock()
	cache.cache[name] = req
}

// 同节点只有一个服务实例，直接使用内存缓存
func checkSimilar(event Event) bool {

	payload := SignalPayload{OutputFields: map[string]string{}}
	payload.ClusterKey = event.Payload["cluster_key"].(string)
	payload.Hostname = event.Payload["hostname"].(string)
	outputFields := event.Payload["output_fields"].(map[string]interface{})
	for k, v := range outputFields {
		payload.OutputFields[k] = v.(string)
	}

	scope := genEventScopeHash(payload)
	if len(scope) == 0 {
		logging.Get().Error().Err(errors.New("event scope empty")).Str("event", event.Name).Interface("payload", payload).Msg("event scope empty")
		return false
	}

	cmdline := getEventCmdline(payload)
	if len(cmdline) == 0 {
		logging.Get().Error().Err(errors.New("event cmdline empty")).Str("event", event.Name).Interface("payload", payload).Msg("event cmdline empty")
		return false
	}
	// 检查缓存
	if cacheEvent, ok := RequestCache.get(event.Name); ok && cacheEvent.scope == scope && cacheEvent.cmdline == cmdline {
		if event.Time.Sub(cacheEvent.time) < time.Millisecond*100 {
			return true
		}
	}
	// 更新缓存
	req := requestMozart{
		name:    event.Name,
		scope:   scope,
		cmdline: cmdline,
		time:    event.Time,
	}
	RequestCache.set(event.Name, req)
	return false
}

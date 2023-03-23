package mozart

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/panjf2000/ants/v2"
	"gopkg.in/yaml.v2"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mozartcommon"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	maxTTL = 30

	envPoolSize     = "MOZART_POOL_SIZE"
	defaultPoolSize = 50

	RuleUpdateOperationClose = 2
	RuleUpdateOperationAdd   = 1
	RuleUpdateOperationDel   = 0
)

type Trigger struct {
	Event map[string]interface{} `json:"event"`
}

type Step struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Code         string `json:"code"`
	RegoQuery    rego.PreparedEvalQuery
	OriginParams interface{}
}

type Rule struct {
	Name    string        `json:"name"`
	Enabled bool          `json:"enabled"`
	Trigger Trigger       `json:"trigger"`
	Steps   []Step        `json:"steps"`
	Type    string        `json:"type"`
	Default BranchDefault `json:"default"`
}

type RulesNew struct {
	rulesWithDefault map[string][]Rule
	otherRules       []Rule
}

type Engine struct {
	rules              map[string][]Rule              // 第一层key为rule的版本
	rulesNew           map[string]map[string]RulesNew // 第一层key为rule的版本
	rulesLock          sync.RWMutex                   // rules有读写需求
	activeRulesVersion string

	pool *ants.PoolWithFunc

	deps depOption
}

func NewMozartEngine(ctx context.Context, options ...option) (*Engine, error) {

	cache = cacheStruct{
		Lock:     sync.Mutex{},
		Data:     make(map[string][]map[string]interface{}),
		Sessions: make(map[string]map[string]interface{}),
	}

	sPoolSize := os.Getenv(envPoolSize)
	poolSize, err := strconv.Atoi(sPoolSize)
	if err != nil {
		poolSize = defaultPoolSize
	}
	pool, err := ants.NewPoolWithFunc(poolSize, job)
	if err != nil {
		return nil, err
	}

	do := depOption{}
	for _, option := range options {
		option(&do)
	}

	go asyncClearCache(ctx)

	e := &Engine{
		rules:    make(map[string][]Rule),
		rulesNew: make(map[string]map[string]RulesNew),
		pool:     pool,
		deps:     do,
	}

	regoPreQueries.init()

	rand.Seed(time.Now().UnixMilli())

	return e, nil
}

func asyncClearCache(ctx context.Context) {
	clearCache := func() {
		cache.Lock.Lock()
		defer cache.Lock.Unlock()
		deleteKs := make([]string, 0)
		now := time.Now()
		for k, vs := range cache.Data {
			j := 0
			for i := len(vs) - 1; i >= 0; i-- {
				eventTime, ok := vs[i]["time"].(time.Time)
				if !ok {
					logging.Get().Error().Err(errors.New("ridiculous, no time in event")).Interface("event", vs[i]).Msg("ridiculous, no time in event")
					continue
				}
				if now.Sub(eventTime) > time.Second*maxTTL {
					break
				} else {
					j = i
				}
			}
			vs = vs[j:]
			if len(vs) == 0 {
				deleteKs = append(deleteKs, k)
			} else {
				cache.Data[k] = vs
			}
		}
		for i := range deleteKs {
			delete(cache.Data, deleteKs[i])
		}

		deleteSKs := make([]string, 0)
		for k, v := range cache.Sessions {
			sEventTime, ok := v["event_time"].(string)
			if ok {
				et, err := time.Parse(time.RFC3339, sEventTime)
				if err == nil && time.Now().Sub(et) <= time.Second*maxTTL {
					continue
				}
			}
			deleteSKs = append(deleteSKs, k)
		}
		for j := range deleteSKs {
			delete(cache.Sessions, deleteSKs[j])
		}
	}

	tick := time.NewTicker(time.Second * 1)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			clearCache()
		}
	}
}

func (e *Engine) UpdateRules(operation int, version string, rules []Rule) error {
	e.rulesLock.Lock()
	defer e.rulesLock.Unlock()

	// 清除数据
	if operation == RuleUpdateOperationDel {
		if len(version) == 0 {
			return nil
		}
		if len(e.rules) <= 1 {
			err := errors.New("try to delete only one version rules")
			logging.Get().Error().Err(err).Str("version", version).Msg("try to delete only one version rules")
			return err
		}
		if _, ok := e.rules[version]; !ok {
			logging.Get().Error().Err(errors.New("no such old version rules")).Str("version", version).Msg("no such old version rules")
		} else {
			delete(e.rules, version)
		}

		if _, ok := e.rulesNew[version]; !ok {
			logging.Get().Error().Err(errors.New("no such old version rulesNew")).Str("version", version).Msg("no such old version rulesNew")
		} else {
			delete(e.rulesNew, version)
		}

	}

	// 增加数据
	if operation == RuleUpdateOperationAdd {
		rulesMap := make(map[string][]Rule)
		for i := range rules {
			key := rules[i].Trigger.Event["name"].(string)
			if key == "" {
				logging.Get().Warn().Msg("invalid rule trigger key")
				continue
			}
			if rs, ok := rulesMap[key]; ok {
				rulesMap[key] = append(rs, rules[i])
			} else {
				rulesMap[key] = []Rule{rules[i]}
			}
		}

		e.rules[version] = rules

		rulesNew := make(map[string]RulesNew)
		for k, v := range rulesMap {
			m := make(map[string][]Rule)
			defaultM := make(map[string]struct{})
			for i := range v {
				if v[i].Default.Enabled {
					defaultM[v[i].Default.ID] = struct{}{}
				}
				if rs, ok := m[v[i].Default.ID]; ok {
					m[v[i].Default.ID] = append(rs, v[i])
				} else {
					m[v[i].Default.ID] = []Rule{v[i]}
				}
			}
			otherRules := make([]Rule, 0)
			for j := range m {
				if _, ok := defaultM[j]; !ok {
					otherRules = append(otherRules, m[j]...)
					delete(m, j)

				}
			}
			rulesNew[k] = RulesNew{
				rulesWithDefault: m,
				otherRules:       otherRules,
			}
		}
		e.rulesNew[version] = rulesNew
	}

	return nil

}

func (e *Engine) LoadFromRuleBytes(ctx context.Context, ruleBytes []byte) ([]Rule, error) {
	data := make([]model.OriginConfig, 0)
	rules := make([]Rule, 0)
	err := yaml.Unmarshal(ruleBytes, &data)
	if err != nil {
		return nil, err
	}

	// mozart
	var mozartConfig []model.ConfigMozart
	var mozartMarco []model.ConfigMozartMarco
	for i := range data {
		if len(data[i].MozartMarco) == 0 {
			continue
		}
		mozartMarco = data[i].MozartMarco
		break
	}

	for i := range data {
		if len(data[i].Mozart) == 0 {
			continue
		}
		mozartConfig = data[i].Mozart
		for j := range data[i].Mozart {
			// 没有配置mozart steps，跳过
			if len(data[i].Mozart[j].Steps) == 0 {
				continue
			}
			if data[i].Mozart[j].Name == "" || data[i].Mozart[j].Trigger == "" {
				logging.Get().Warn().Str("trigger", data[i].Mozart[j].Trigger).Str("name", data[i].Mozart[j].Name).Msg("invalid rule key")
				continue
			}

			values := map[string]interface{}{"0": map[string]interface{}{}}
			for k := range data[i].Mozart[j].Steps {
				innerValues, err := mozartcommon.ExtractValues(ctx, data[i].Mozart[j].Steps[k], mozartMarco, "0")
				if err != nil {
					return nil, err
				}
				for ik, iv := range innerValues {
					values["0"].(map[string]interface{})[ik] = iv
				}
			}

			stepsTotal := make([]StepMore, 0)
			var stepsMatrix []StepMore
			for k := range data[i].Mozart[j].Steps {
				stepsMatrix, err = e.configStep2MozartStep(ctx, data[i].Mozart[j].Steps[k], mozartMarco, values, "0")
				if err != nil {
					return nil, err
				}
				if len(stepsMatrix) == 0 {
					continue
				}
				newStepsTotal := make([]StepMore, 0)
				if len(stepsTotal) == 0 {
					newStepsTotal = stepsMatrix
				} else {
					for m := 0; m < len(stepsMatrix); m++ {
						nst := make([]StepMore, len(stepsTotal))
						for n := 0; n < len(stepsTotal); n++ {
							nst[n].Steps = append(stepsTotal[n].Steps, stepsMatrix[m].Steps...)
							nst[n].Key = correctKey(stepsTotal[n].Key, stepsMatrix[m].Key)
							nst[n].Default = defaultOR(stepsTotal[n].Default, stepsMatrix[m].Default) // todo: 分支嵌套分支，有问题
						}
						newStepsTotal = append(newStepsTotal, nst...)
					}
				}
				stepsTotal = newStepsTotal
			}

			for ii := range stepsTotal {
				for jj := range stepsTotal[ii].Steps {
					if stepsTotal[ii].Steps[jj].Name == "checkRegexMatch" { // 正则里有太多语法，和我们的替换赋值有冲突
						continue
					}
					stepsTotal[ii].Steps[jj].Code, err = convertValuesByKey(stepsTotal[ii].Steps[jj].Code, stepsTotal[ii].Key, values)
					if err != nil {
						continue
					}
				}
				desc, err := convertValuesByKey(data[i].Mozart[j].Info.Desc.En, stepsTotal[ii].Key, values)
				if err != nil {
					continue
				}

				rule := Rule{
					Name:    desc,
					Enabled: data[i].Mozart[j].Enabled,
					Trigger: Trigger{Event: map[string]interface{}{
						"name": data[i].Mozart[j].Trigger,
					}},
					Steps:   stepsTotal[ii].Steps,
					Type:    "mozart",
					Default: stepsTotal[ii].Default,
				}
				rules = append(rules, rule)
			}

		}
		break
	}

	// 非mozart
	for i := range data {
		if len(data[i].Mozart) != 0 || data[i].Rule == "" {
			continue
		}

		// 纯关联规则，跳过
		if util.ContainsString(data[i].Tags, "related") && !util.ContainsString(data[i].Tags, "triggered") {
			continue
		}

		// 不是关联也不是触发，普通falco规则，追加mozart基础规则
		if !util.ContainsString(data[i].Tags, "related") && !util.ContainsString(data[i].Tags, "triggered") {
			steps := e.makeupBasicSteps(ctx, data[i].Rule)
			rules = append(rules, Rule{
				Name:    data[i].Rule,
				Enabled: true,
				Trigger: Trigger{Event: map[string]interface{}{
					"name": data[i].Rule,
				}},
				Steps: steps,
				Type:  "basic",
			})
		}

		// 如果触发信号为高危，则追加一条fallback规则（当没有任何关联信号时，直接上报触发信号）
		if util.ContainsString(data[i].Tags, "triggered") && rtdetect.ComparePriority(data[i].Priority, "ERROR") {
			steps := e.makeupFallbackSteps(ctx, data[i].Rule, mozartConfig)
			rules = append(rules, Rule{
				Name:    data[i].Rule,
				Enabled: true,
				Trigger: Trigger{Event: map[string]interface{}{
					"name": data[i].Rule,
				}},
				Steps: steps,
				Type:  "fallback",
			})
		}
		continue
	}

	err = e.fillUpRegoPreQueries(ctx, rules)
	if err != nil {
		return rules, err
	}
	return rules, nil
}

type RegoPreQueries struct {
	lock    sync.Mutex
	queries map[string]*rego.PreparedEvalQuery
}

var regoPreQueries RegoPreQueries

func (rpq *RegoPreQueries) init() {
	rpq.queries = make(map[string]*rego.PreparedEvalQuery, 0)
}

func (rpq *RegoPreQueries) get(key string) (*rego.PreparedEvalQuery, error) {
	rpq.lock.Lock()
	defer rpq.lock.Unlock()
	query, ok := rpq.queries[key]
	if !ok {
		return query, errors.New("no such query: " + key)
	}
	return query, nil
}

func (e *Engine) fillUpRegoPreQueries(ctx context.Context, rules []Rule) error {
	regoPreQueries.lock.Lock()
	defer regoPreQueries.lock.Unlock()

	for k := range rules {
		for j := range rules[k].Steps {
			step := rules[k].Steps[j]
			r, err := e.configToRegoQuery(step.Name, step.Code)
			if err != nil {
				logging.Get().Error().Err(err).Msg("invalid step for rego prepare")
				return err
			}
			regoPreQueries.queries[step.Code] = &r
		}
	}
	return nil
}

func convertValuesByKey(format string, key string, values map[string]interface{}) (string, error) {
	var err error
	var ok bool

	keyElems := strings.Split(key, "-")
	keys := make([]string, len(keyElems))
	for i := range keyElems {
		keys[i] = strings.Join(keyElems[:i+1], "-")
	}

	originVs := values
	keyValues := make([]map[string]interface{}, 0)
	for j := range keys {
		vs := make(map[string]interface{})
		originVs, ok = originVs[keys[j]].(map[string]interface{})
		if !ok {
			break
		}
		for k, v := range originVs {
			if mozartcommon.CheckKey(k) {
				continue
			}
			vs[k] = v
		}
		keyValues = append(keyValues, vs)
	}

	var iFormat interface{}
	iFormat = format
	for k := len(keyValues) - 1; k >= 0; k-- {
		iFormat, err = mozartcommon.TemplateFormat(iFormat, keyValues[k])
		if err != nil {
			return "", err
		}
	}

	return iFormat.(string), nil
}

type BranchDefault struct {
	Enabled bool   `json:"enabled"`
	ID      string `json:"id"`
}

func defaultOR(a, b BranchDefault) BranchDefault {
	if b.Enabled {
		return b
	} else {
		return a
	}
}

type StepMore struct {
	Steps   []Step
	Key     string
	Default BranchDefault
}

func correctKey(k1, k2 string) string {
	if len(k1) > len(k2) {
		return k1
	}
	return k2
}

func (e *Engine) configStep2MozartStep(ctx context.Context, configStep model.ConfigMozartStep, mozartMarco []model.ConfigMozartMarco, values map[string]interface{}, key string) ([]StepMore, error) {
	var stepMatrix []StepMore
	var err error

	switch configStep.Name {
	// 纯表达式
	case "checkExpression":
		stepMatrix = []StepMore{{Steps: []Step{simpleStep(configMozartStepParamsCheckExpression(configStep.Params.(string)).rCode(), configStep)}, Key: key}}
	case "execExpression":
		stepMatrix = []StepMore{{Steps: []Step{simpleStep(configMozartStepParamsExecExpression(configStep.Params.(string)).rCode(), configStep)}, Key: key}}

	// 内置函数
	case "checkValue":
		stepMatrix = []StepMore{{Steps: []Step{simpleStep(configMozartStepParamsCheckValue(configStep.Params.([]interface{})).rCode(), configStep)}, Key: key}}
	case "checkRelatedExists":
		stepMatrix = []StepMore{{Steps: []Step{simpleStep(configMozartStepParamsCheckRelatedExists(configStep.Params.([]interface{})).rCode(), configStep)}, Key: key}}
	case "checkRuleRecentCount":
		stepMatrix = []StepMore{{Steps: []Step{simpleStep(configMozartStepParamsCheckRuleRecentCount(configStep.Params.([]interface{})).rCode(), configStep)}, Key: key}}
	case "checkRegexMatch":
		stepMatrix = []StepMore{{Steps: []Step{simpleStep(configMozartStepParamsCheckRegexMatch(configStep.Params.([]interface{})).rCode(), configStep)}, Key: key}}
	case "execGenerateSignal":
		p := configStep.Params.(map[interface{}]interface{})
		mp := make(map[string]interface{}, len(p))
		for k, v := range p {
			mp[k.(string)] = v
		}
		configStep.Params = mp
		stepMatrix = []StepMore{{Steps: []Step{simpleStep(configMozartStepParamsExecGenerateSignal(mp).rCode(), configStep)}, Key: key}}
	case "execSendPalace":
		stepMatrix = []StepMore{{Steps: []Step{simpleStep(configMozartStepParamsExecSendPalace(configStep.Params.(string)).rCode(), configStep)}, Key: key}}

	case "branches":
		var innerBranchStepMatrix []StepMore
		branchName := strings.TrimPrefix(configStep.Params.(string), marcoPrefix)
		branchID := branchName + strconv.Itoa(rand.Intn(99999999999))
		foundBranchMarco := false
		for i := range mozartMarco {
			if mozartMarco[i].Key != branchName {
				continue
			}
			foundBranchMarco = true
			for j := range mozartMarco[i].Branches {
				if !mozartMarco[i].Branches[j].Enabled && !mozartMarco[i].Branches[j].Default {
					continue
				}
				branchMatrix := make([]StepMore, 0)
				branchKey := key + "-" + strconv.Itoa(j)

				for k := range mozartMarco[i].Branches[j].Steps {
					innerBranchStepMatrix, err = e.configStep2MozartStep(ctx, mozartMarco[i].Branches[j].Steps[k], mozartMarco, values, branchKey)
					if err != nil {
						return nil, err
					}
					if len(innerBranchStepMatrix) == 0 { // defineValue等无需运行的step
						continue
					}
					if len(innerBranchStepMatrix) == 1 && len(innerBranchStepMatrix[0].Steps) == 1 { // basic simple step
						if len(branchMatrix) == 0 { // 长度为0，初始化
							branchMatrix = append(branchMatrix, innerBranchStepMatrix[0])
						} else { // 已有多个分支，将当前的simple step加入已有的分支尾端
							for m := range branchMatrix {
								branchMatrix[m].Steps = append(branchMatrix[m].Steps, innerBranchStepMatrix[0].Steps[0])
								branchMatrix[m].Key = correctKey(branchMatrix[m].Key, innerBranchStepMatrix[0].Key)
							}
						}
					} else { // embedded branches
						newStepsTotal := make([]StepMore, 0)
						if len(branchMatrix) == 0 {
							newStepsTotal = innerBranchStepMatrix
						} else {
							for m := 0; m < len(innerBranchStepMatrix); m++ {
								nst := make([]StepMore, len(branchMatrix))
								for n := 0; n < len(branchMatrix); n++ {
									nst[n].Steps = append(branchMatrix[n].Steps, innerBranchStepMatrix[m].Steps...)
									nst[n].Key = correctKey(branchMatrix[n].Key, innerBranchStepMatrix[m].Key)
								}
								newStepsTotal = append(newStepsTotal, nst...)
							}
						}
						branchMatrix = newStepsTotal
					}
				}
				for k := range branchMatrix {
					branchMatrix[k].Default.ID = branchID
					if mozartMarco[i].Branches[j].Default {
						branchMatrix[k].Default.Enabled = true
					}
				}
				stepMatrix = append(stepMatrix, branchMatrix...)
			}
		}
		if !foundBranchMarco {
			return stepMatrix, errors.New("no valid branch marco: " + branchName)
		}
	case "defineValue":
		p := configStep.Params.(map[interface{}]interface{})
		for k, v := range p {
			values[k.(string)] = v
		}
	default:
		err = errors.New("no match step name")
		logging.Get().Error().Err(err).Str("stepName", configStep.Name).Msg("no match step name")
		return stepMatrix, err
	}

	return stepMatrix, nil
}

func simpleStep(code string, config model.ConfigMozartStep) Step {
	step := Step{Code: code}
	step.Name = config.Name
	if step.Name == "branches" {
		step.Type = "branches"
	} else if strings.HasPrefix(step.Name, "check") {
		step.Type = "check"
	} else {
		step.Type = "exec"
	}
	step.OriginParams = config.Params
	return step
}

func (e *Engine) makeupFallbackSteps(ctx context.Context, rule string, configMozartList []model.ConfigMozart) []Step {
	var err error
	steps := make([]Step, 0)
	relatedMap := make(map[interface{}]struct{})
	// checkRelatedNotExists
	for i := range configMozartList {
		if configMozartList[i].Trigger != rule {
			continue
		}
		for j := range configMozartList[i].Steps {
			if configMozartList[i].Steps[j].Name == "checkRelatedExists" {
				if _, ok := relatedMap[configMozartList[i].Steps[j].Params.([]interface{})[0]]; ok {
					continue
				}
				step := Step{}
				step.Name = "checkRelatedNotExists"
				step.Type = "check"
				step.OriginParams = configMozartList[i].Steps[j].Params
				step.Code = configMozartStepParamsCheckRelatedNotExists(configMozartList[i].Steps[j].Params.([]interface{})).rCode()
				if err != nil {
					continue
				}
				relatedMap[configMozartList[i].Steps[j].Params.([]interface{})[0]] = struct{}{}
				steps = append(steps, step)
			}
		}
	}

	// execGenerateSignal
	step := Step{}
	mp := make(map[string]interface{})
	mp["rule"] = rule
	step.Code = configMozartStepParamsExecGenerateSignal(mp).rCode()
	if err != nil {
		logging.Get().Error().Err(err).Str("code", step.Code).Msg("prepareExecGenerateSignal fails")
		return steps
	}
	step.Name = "execGenerateSignal"
	step.Type = "exec"
	step.OriginParams = mp
	steps = append(steps, step)

	// execSendPalace
	step = Step{}
	step.Code = configMozartStepParamsExecSendPalace("").rCode()
	if err != nil {
		logging.Get().Error().Err(err).Str("code", step.Code).Msg("prepareExecSendPalace fails")
		return steps
	}
	step.Name = "execSendPalace"
	step.Type = "exec"
	step.OriginParams = mp
	steps = append(steps, step)

	return steps
}

func (e *Engine) makeupBasicSteps(ctx context.Context, rule string) []Step {
	var err error
	steps := make([]Step, 0)
	// execGenerateSignal
	step := Step{}
	mp := make(map[string]interface{})
	mp["rule"] = rule
	step.Code = configMozartStepParamsExecGenerateSignal(mp).rCode()
	if err != nil {
		logging.Get().Error().Err(err).Str("code", step.Code).Msg("prepareExecGenerateSignal fails")
		return steps
	}
	step.Name = "execGenerateSignal"
	step.Type = "exec"
	step.OriginParams = mp
	steps = append(steps, step)

	// execSendPalace
	step = Step{}
	step.Code = configMozartStepParamsExecSendPalace("").rCode()
	if err != nil {
		logging.Get().Error().Err(err).Str("code", step.Code).Msg("prepareExecSendPalace fails")
		return steps
	}
	step.Name = "execSendPalace"
	step.Type = "exec"
	step.OriginParams = ""
	steps = append(steps, step)

	return steps
}

func (e *Engine) SetActiveRulesVersion(v string) {
	e.activeRulesVersion = v
}

func (e *Engine) GetActiveRulesVersion() string {
	return e.activeRulesVersion
}

func (e *Engine) GetActiveRules() ([]Rule, bool) {
	e.rulesLock.RLock()
	defer e.rulesLock.RUnlock()
	rules, ok := e.rules[e.activeRulesVersion]
	return rules, ok
}

func (e *Engine) Rules(v, key string) (RulesNew, bool) {
	e.rulesLock.RLock()
	defer e.rulesLock.RUnlock()
	rules, ok := e.rulesNew[v][key]
	return rules, ok
}

func (e *Engine) Run(event Event) error {
	if e.pool.Free() == 0 { // todo: 可以考虑和 pool.waiting() 一起做控制
		err := errors.New("exhausted mozart pool")
		logging.Get().Error().Err(err).Int("pool_size", e.pool.Cap()).Msg("exhausted mozart pool")
		return err
	}
	err := e.pool.Invoke(jobArgs{Event: event, e: e})
	return err
}

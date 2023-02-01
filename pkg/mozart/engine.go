package mozart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/panjf2000/ants/v2"
	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
	Name    string  `json:"name"`
	Enabled bool    `json:"enabled"`
	Trigger Trigger `json:"trigger"`
	Steps   []Step  `json:"steps"`
	Type    string  `json:"type"`
}

type UpdateData struct {
	Operation int // 0-清除数据；1-增加数据
	Version   string
	Rules     []Rule
}

type Engine struct {
	rules              map[string][]Rule            // 第一层key为rule的版本
	rulesMap           map[string]map[string][]Rule // 第一层key为rule的版本
	rulesLock          sync.RWMutex                 // rules有读写需求
	activeRulesVersion string

	pool *ants.PoolWithFunc

	deps depOption
}

var regoPool RegoPool

func NewMozartEngine(ctx context.Context, options ...Option) (*Engine, error) {

	Cache = CacheStruct{
		Lock: sync.Mutex{},
		Data: make(map[string][]map[string]interface{}),
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
		rulesMap: make(map[string]map[string][]Rule),
		pool:     pool,
		deps:     do,
	}

	regoPool.Init()

	return e, nil
}

func asyncClearCache(ctx context.Context) {
	clearCache := func() {
		Cache.Lock.Lock()
		defer Cache.Lock.Unlock()
		deleteKs := make([]string, 0)
		for k, vs := range Cache.Data {
			nvs := make([]map[string]interface{}, 0)
			for i := range vs {
				eventTime, ok := vs[i]["time"].(time.Time)
				if !ok {
					logging.Get().Error().Err(errors.New("ridiculous, no time in event")).Interface("event", vs[i]).Msg("ridiculous, no time in event")
					continue
				}
				if time.Now().Sub(eventTime) > time.Second*maxTTL {
					continue
				} else {
					nvs = append(nvs, vs[i])
				}
			}
			if len(nvs) == 0 {
				deleteKs = append(deleteKs, k)
			} else {
				Cache.Data[k] = nvs
			}
		}
		for i := range deleteKs {
			delete(Cache.Data, deleteKs[i])
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

		if _, ok := e.rulesMap[version]; !ok {
			logging.Get().Error().Err(errors.New("no such old version rulesMap")).Str("version", version).Msg("no such old version rulesMap")
		} else {
			delete(e.rulesMap, version)
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
		e.rulesMap[version] = rulesMap

	}

	return nil

}

func (e *Engine) LoadFromRuleBytes(ctx context.Context, ruleBytes []byte) ([]Rule, error) {
	config := model.OriginConfigs{}
	rules := make([]Rule, 0)
	v := viper.New()
	v.SetConfigType("yaml")
	prefix := []byte("config:\n") // fixme: 加这个前缀的目的是因为：viper不能读取纯list的yaml，可能是我不会

	err := v.ReadConfig(bytes.NewBuffer(append(prefix, ruleBytes...)))
	if err != nil {
		return rules, err
	}
	if err := v.Unmarshal(&config); err != nil {
		return rules, err
	}

	data := config.Config
	for i := range data {
		// 非mozart
		if len(data[i].Mozart) == 0 && data[i].Rule != "" {
			// 纯关联规则，跳过
			if util.ContainsString(data[i].Tags, "related") && !util.ContainsString(data[i].Tags, "triggered") {
				continue
			}

			// 不是关联也不是触发，普通falco规则，追加mozart基础规则
			if !util.ContainsString(data[i].Tags, "related") && !util.ContainsString(data[i].Tags, "triggered") {
				rules = append(rules, Rule{
					Name:    data[i].Rule,
					Enabled: true,
					Trigger: Trigger{Event: map[string]interface{}{
						"name": data[i].Rule,
					}},
					Steps: e.makeupBasicSteps(ctx, data[i].Rule),
					Type:  "basic",
				})
			}

			// 如果触发信号为高危，则追加一条fallback规则（当没有任何关联信号时，直接上报触发信号）
			if util.ContainsString(data[i].Tags, "triggered") && rtdetect.ComparePriority(data[i].Priority, "ERROR") {
				rules = append(rules, Rule{
					Name:    data[i].Rule,
					Enabled: true,
					Trigger: Trigger{Event: map[string]interface{}{
						"name": data[i].Rule,
					}},
					Steps: e.makeupFallbackSteps(ctx, data[i].Rule, data[i].Mozart),
					Type:  "fallback",
				})
			}
			continue
		}

		// mozart
		for j := range data[i].Mozart {
			// 没有配置mozart steps，跳过
			if len(data[i].Mozart[j].Steps) == 0 {
				continue
			}
			steps := make([]Step, len(data[i].Mozart[j].Steps))
			for k := range data[i].Mozart[j].Steps {
				steps[k] = e.configStep2MozartStep(ctx, data[i].Mozart[j].Steps[k])
			}
			rule := Rule{
				Name:    data[i].Mozart[j].Name,
				Enabled: data[i].Mozart[j].Enabled,
				Trigger: Trigger{Event: map[string]interface{}{
					"name": data[i].Mozart[j].Trigger,
				}},
				Steps: steps,
				Type:  "mozart",
			}
			if data[i].Mozart[j].Name == "" || data[i].Mozart[j].Trigger == "" {
				logging.Get().Warn().Str("trigger", data[i].Mozart[j].Trigger).Str("name", data[i].Mozart[j].Name).Msg("invalid rule key")
				continue
			}
			rules = append(rules, rule)
		}

	}

	return rules, nil
}

type RegoPool struct {
	Pool map[string]chan map[string]*rego.Rego
	Lock sync.Mutex
}

func (p *RegoPool) Init() {
	m := make(map[string]chan map[string]*rego.Rego)
	p.Pool = m
	p.Lock = sync.Mutex{}
}

func (p *RegoPool) Get(key string) (map[string]*rego.Rego, error) {
	regoPool.Lock.Lock()
	defer regoPool.Lock.Unlock()
	pool, ok := p.Pool[key]
	if !ok {
		err := fmt.Errorf("no invalid key pool")
		logging.Get().Error().Err(err).Str("key", key).Int("poolsize", len(p.Pool)).Msg("no invalid key pool?!")
		return nil, err
	}
	return <-pool, nil
}

func (p *RegoPool) Put(key string, mrq map[string]*rego.Rego) {
	regoPool.Lock.Lock()
	defer regoPool.Lock.Unlock()
	pool, ok := p.Pool[key]
	if !ok {
		logging.Get().Error().Err(fmt.Errorf("no invalid key pool")).Str("key", key).Int("poolsize", len(p.Pool)).Msg("no invalid key pool?!")
		return
	}
	pool <- mrq
}

func (e *Engine) appendMozartRegoPool(ctx context.Context, steps []Step, key string) {
	regoPool.Lock.Lock()
	defer regoPool.Lock.Unlock()

	if _, ok := regoPool.Pool[key]; ok {
		return
	}

	regoQueries := make(map[string]*rego.Rego, 0)
	for i := range steps {
		step := steps[i]
		var r *rego.Rego
		r = rego.New(
			rego.Query(step.Code),
		)

		regoQueries[step.Code] = r
	}
	sPoolSize := os.Getenv("MOZART_POOL_SIZE")
	poolSize, err := strconv.Atoi(sPoolSize)
	if err != nil {
		poolSize = defaultPoolSize
	}
	ch := make(chan map[string]*rego.Rego, poolSize)
	for i := 0; i < poolSize; i++ {
		ch <- regoQueries
	}
	regoPool.Pool[key] = ch
}

func (e *Engine) configStep2MozartStep(ctx context.Context, configStep model.ConfigMozartStep) Step {
	step := Step{}

	var err error
	switch configStep.Name {
	// 纯表达式
	case "checkExpression":
		step.Code = ConfigMozartStepParamsCheckExpression(configStep.Params.(string)).RCode()
	case "execExpression":
		step.Code = ConfigMozartStepParamsExecExpression(configStep.Params.(string)).RCode()

	// 内置函数
	case "checkValue":
		step.Code = ConfigMozartStepParamsCheckValue(configStep.Params.([]interface{})).RCode()
	case "checkRelatedExists":
		step.Code = ConfigMozartStepParamsCheckRelatedExists(configStep.Params.([]interface{})).RCode()
	case "execGenerateSignal":
		p := configStep.Params.(map[interface{}]interface{})
		mp := make(map[string]interface{}, len(p))
		for k, v := range p {
			mp[k.(string)] = v
		}
		configStep.Params = mp
		step.Code = ConfigMozartStepParamsExecGenerateSignal(mp).RCode()
	case "execSendPalace":
		step.Code = ConfigMozartStepParamsExecSendPalace(configStep.Params.(string)).RCode()
	}
	if err != nil {
		panic(err)
	}

	step.Name = configStep.Name
	if strings.HasPrefix(step.Name, "check") {
		step.Type = "check"
	} else {
		step.Type = "exec"
	}
	step.OriginParams = configStep.Params
	return step
}

func (e *Engine) makeupFallbackSteps(ctx context.Context, rule string, configMozartList []model.ConfigMozart) []Step {
	var err error
	steps := make([]Step, 0)
	relatedMap := make(map[interface{}]struct{})
	// checkRelatedNotExists
	for i := range configMozartList {
		for j := range configMozartList[i].Steps {
			if configMozartList[i].Steps[j].Name == "checkRelatedExists" {
				if _, ok := relatedMap[configMozartList[i].Steps[j].Params.([]interface{})[0]]; ok {
					continue
				}
				step := Step{}
				step.Name = "checkRelatedNotExists"
				step.Type = "check"
				step.OriginParams = configMozartList[i].Steps[j].Params
				step.Code = ConfigMozartStepParamsCheckRelatedNotExists(configMozartList[i].Steps[j].Params.([]interface{})).RCode()
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
	step.Code = ConfigMozartStepParamsExecGenerateSignal(mp).RCode()
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
	step.Code = ConfigMozartStepParamsExecSendPalace("").RCode()
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
	step.Code = ConfigMozartStepParamsExecGenerateSignal(mp).RCode()
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
	step.Code = ConfigMozartStepParamsExecSendPalace("").RCode()
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

func (e *Engine) Rules(v, key string) ([]Rule, bool) {
	e.rulesLock.RLock()
	defer e.rulesLock.RUnlock()
	rules, ok := e.rulesMap[v][key]
	return rules, ok
}

func (e *Engine) Run(event Event) error {
	err := e.pool.Invoke(jobArgs{Event: event, e: e})
	return err
}

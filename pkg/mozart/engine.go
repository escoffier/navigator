package mozart

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/panjf2000/ants/v2"

	"gitlab.com/security-rd/go-pkg/logging"
	gpModel "gitlab.com/security-rd/go-pkg/model"
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

type Related struct {
	RuleName string `json:"rule_name"`
}

type Step struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Code         string `json:"code"`
	RegoQuery    rego.PreparedEvalQuery
	OriginParams interface{}
}

type Rule struct {
	Key      string                `json:"key"` // 原始mozart规则定义的key
	Name     string                `json:"name"`
	Enabled  bool                  `json:"enabled"`
	Trigger  gpModel.Trigger       `json:"trigger"`  // 触发条件
	Relateds []gpModel.Related     `json:"relateds"` // 关联条件
	Steps    []gpModel.Step        `json:"steps"`
	Type     string                `json:"type"`
	Default  gpModel.BranchDefault `json:"default"`
}

type rulesWithDefault struct {
	rules   []Rule // 所有该default分支相关的规则，默认串行执行。
	runType string // branches_serial - 串行，branches_parallel - 并行
}

type RulesNew struct {
	rulesWithDefault map[string]rulesWithDefault // 有default分支的规则，key位defaultID
	otherRules       []Rule                      // 其他不需要default分支的规则，当前为并行执行
}

type Engine struct {
	rules              map[string][]Rule              // 第一层key为rule的版本，value为该版本的rules列表
	rulesNew           map[string]map[string]RulesNew // 第一层key为rule的版本，第二层key为trigger，value为RulesNew结构
	falcoMozartMap     map[string]map[string][]string // 第一层key为rule的版本，第二次key为falco key，value为mozart keys
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
		rules:          make(map[string][]Rule),
		rulesNew:       make(map[string]map[string]RulesNew),
		falcoMozartMap: make(map[string]map[string][]string),
		pool:           pool,
		deps:           do,
	}

	regoPreQueries.init()

	RequestCache.init()

	initHangupQueue(e)

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

func (e *Engine) UpdateRules(operation int, version string, rules []Rule, falcoMozartMap map[string][]string) error {
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

		if len(e.falcoMozartMap) <= 1 {
			err := errors.New("try to delete only one version falcoMozartMap")
			logging.Get().Error().Err(err).Str("version", version).Msg("try to delete only one version falcoMozartMap")
			return err
		}
		if _, ok := e.falcoMozartMap[version]; !ok {
			logging.Get().Error().Err(errors.New("no such old version falcoMozartMap")).Str("version", version).Msg("no such old version falcoMozartMap")
		} else {
			delete(e.falcoMozartMap, version)
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
			m := make(map[string]rulesWithDefault)

			defaultM := make(map[string]struct{})
			for i := range v {
				if v[i].Default.Enabled != nil {
					defaultM[v[i].Default.ID] = struct{}{}
				}
				if rs, ok := m[v[i].Default.ID]; ok {
					m[v[i].Default.ID] = rulesWithDefault{
						rules:   append(rs.rules, v[i]),
						runType: rs.runType,
					}
				} else {
					m[v[i].Default.ID] = rulesWithDefault{
						rules:   []Rule{v[i]},
						runType: v[i].Default.RunType,
					}
				}
			}

			otherRules := make([]Rule, 0)
			for j := range m {
				if _, ok := defaultM[j]; !ok {
					otherRules = append(otherRules, m[j].rules...)
					delete(m, j)

				}
			}
			rulesNew[k] = RulesNew{
				rulesWithDefault: m,
				otherRules:       otherRules,
			}
		}
		e.rulesNew[version] = rulesNew

		e.falcoMozartMap[version] = falcoMozartMap
	}

	return nil

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

func (e *Engine) FillUpRegoPreQueries(ctx context.Context, rules []Rule) error {
	regoPreQueries.lock.Lock()
	defer regoPreQueries.lock.Unlock()

	for k := range rules {
		ruleRego := make(map[string]*rego.PreparedEvalQuery)
		continueToNextRule := false
		for j := range rules[k].Steps {
			step := rules[k].Steps[j]
			logging.Get().Debug().Str("name", step.Name).Str("code", step.Code).Msg("MOZART_DEBUG - build regoQeury")
			r, err := e.configToRegoQuery(step.Name, step.Code)
			if err != nil {
				// 有step不支持的时候，跳过该规则，继续加载后续的规则
				logging.Get().Error().Err(err).Str("name", step.Name).Str("code", step.Code).Msg("invalid step for rego prepare")
				continueToNextRule = true
				break
			}
			ruleRego[step.Code] = &r
		}
		if continueToNextRule {
			continue
		}
		for code, regoQeury := range ruleRego {
			regoPreQueries.queries[code] = regoQeury
		}
	}
	return nil
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
	logging.Get().Debug().Int("pool free", e.pool.Free()).Int("pool running", e.pool.Running()).Int("pool waiting", e.pool.Waiting()).Msg("MOZART_DEBUG - pool")
	logging.Get().Debug().Str("input falco", event.Name).Msg("MOZART_DEBUG - input falco")

	if ok := checkSimilar(event); ok {
		logging.Get().Debug().Str("input falco", event.Name).Msg("MOZART_DEBUG - omit similar falco")
		return nil
	}

	if e.pool.Free() == 0 { // todo: 可以考虑和 pool.waiting() 一起做控制
		err := errors.New("exhausted mozart pool")
		logging.Get().Error().Err(err).Int("pool_size", e.pool.Cap()).Msg("exhausted mozart pool")
		return err
	}

	falcoMozartMap, ok := e.falcoMozartMap[e.GetActiveRulesVersion()]
	if !ok {
		err := fmt.Errorf("no such falcoMozartMap version: %s", e.GetActiveRulesVersion())
		logging.Get().Error().Err(err).Msg("")
		return err
	}

	mozartRules, ok := falcoMozartMap[event.Name]
	if !ok {
		err := fmt.Errorf("no such falco rule: %s", event.Name)
		logging.Get().Error().Err(err).Msg("")
		return err
	}
	logging.Get().Debug().Str("input mozart", strings.Join(mozartRules, " | ")).Msg("MOZART_DEBUG - input mozart")

	wg := sync.WaitGroup{}
	var err error
	for i := range mozartRules {
		event.Name = mozartRules[i]
		wg.Add(1)
		go func(newEvent Event) {
			defer wg.Done()
			ie := e.runMozart(newEvent)
			if ie != nil {
				logging.Get().Error().Err(ie).Msg("mozart run fails")
				err = fmt.Errorf("%w", ie)
			}
		}(event)
	}
	wg.Wait()

	return err
}

func (e *Engine) runMozart(event Event) error {
	logging.Get().Debug().Str("active version", e.GetActiveRulesVersion()).Str("event name", event.Name).Msg("MOZART_DEBUG - job")

	event.Time = event.Time.Local()

	jsonEvent := map[string]interface{}{
		"name":    event.Name,
		"time":    event.Time,
		"payload": event.Payload,
	}

	err := cacheGlobal(event, jsonEvent)
	if err != nil {
		logging.Get().Error().Err(err).Interface("event", event).Msg("cacheGlobal event fails")
		return err
	}

	rules, ok := e.Rules(e.GetActiveRulesVersion(), event.Name)
	if !ok {
		logging.Get().Debug().Str("active version", e.GetActiveRulesVersion()).Str("event name", event.Name).Msg("MOZART_DEBUG - no active rule")
		return nil
	}

	return e.pool.Invoke(jobArgs{Event: event, Rules: rules, JsonEvent: jsonEvent, SessionStatus: map[string]interface{}{}})

}

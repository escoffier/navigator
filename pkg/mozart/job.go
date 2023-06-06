package mozart

import (
	"context"
	"math/rand"
	"strconv"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"github.com/open-policy-agent/opa/rego"

	"gitlab.com/security-rd/go-pkg/logging"
)

type jobArgs struct {
	Event         Event
	Rules         RulesNew
	JsonEvent     map[string]interface{}
	SessionStatus map[string]interface{}
}

func job(iArg interface{}) {

	args, _ := iArg.(jobArgs)
	event := args.Event
	rules := args.Rules
	jsonEvent := args.JsonEvent
	sessionStatus := args.SessionStatus

	// check sessionStatus to continue
	for k := range rules.rulesWithDefault {
		lastRulesWithDefault, ok := sessionStatus["rulesWithDefault"]
		if ok && lastRulesWithDefault != k {
			continue
		}
		someBranchSucceed := false
		hangup := false
		defaultRuleIndex := -1
		for j := range rules.rulesWithDefault[k].rules {
			if rules.rulesWithDefault[k].rules[j].Default.Enabled != nil && *rules.rulesWithDefault[k].rules[j].Default.Enabled {
				defaultRuleIndex = j
				break
			}
		}
		if rules.rulesWithDefault[k].runType == "branches_parallel" { // 并行

		} else { // 串行：branches_serial 或 默认
			for j := range rules.rulesWithDefault[k].rules {
				if j == defaultRuleIndex {
					continue
				}
				lastRulesWithDefaultRules, ok := sessionStatus["rulesWithDefault.rules"].(int)
				if ok && lastRulesWithDefaultRules > j {
					continue
				}
				if !rules.rulesWithDefault[k].rules[j].Enabled {
					logging.Get().Debug().Str("non-default rule name", rules.rulesWithDefault[k].rules[j].Name).Msg("MOZART_DEBUG - rule not enabled")
					continue
				}
				// 暂时做成串行，后面考虑用配置字段支持串行或并行的配置
				logging.Get().Debug().Str("non-default rule name", rules.rulesWithDefault[k].rules[j].Name).Msg("MOZART_DEBUG - run rule")
				result, status := runSteps(event, rules.rulesWithDefault[k].rules[j], jsonEvent)
				if result == 1 {
					someBranchSucceed = true
					break
				} else if result == 2 {
					// send work to hangup queue
					nextTime, _ := status["next_time"].(string)
					t, _ := time.Parse(time.RFC3339, nextTime)
					status["rulesWithDefault"] = k
					status["rulesWithDefault.rules"] = j
					sessionHangupQueue <- work{
						Event:         event,
						Rules:         rules,
						JsonEvent:     jsonEvent,
						SessionStatus: status,
						NextTime:      t,
					}
					hangup = true
					break
				}
			}
			if hangup {
				continue
			}
			if !someBranchSucceed && defaultRuleIndex != -1 {
				lastRulesWithDefaultRules, ok := sessionStatus["rulesWithDefault.default"].(int)
				if ok && lastRulesWithDefaultRules != defaultRuleIndex {
					continue
				}
				// 其他分支全部失败，执行default分支
				logging.Get().Debug().Str("default rule name", rules.rulesWithDefault[k].rules[defaultRuleIndex].Name).Msg("MOZART_DEBUG - run rule")
				result, status := runSteps(event, rules.rulesWithDefault[k].rules[defaultRuleIndex], jsonEvent)
				if result == 2 {
					// send work to hangup queue
					nextTime, _ := status["next_time"].(string)
					t, _ := time.Parse(time.RFC3339, nextTime)
					status["rulesWithDefault"] = k
					status["rulesWithDefault.default"] = defaultRuleIndex
					sessionHangupQueue <- work{
						Event:         event,
						Rules:         rules,
						JsonEvent:     jsonEvent,
						SessionStatus: status,
						NextTime:      t,
					}
				}
			}
		}
	}

	wg := sync.WaitGroup{}
	for j := range rules.otherRules {
		otherRulesIndex, ok := sessionStatus["otherRules"].(int)
		if ok && otherRulesIndex != j {
			continue
		}
		if !rules.otherRules[j].Enabled {
			continue
		}
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			logging.Get().Debug().Str("other rule name", rules.otherRules[k].Name).Msg("MOZART_DEBUG - run rule")
			result, status := runSteps(event, rules.otherRules[k], jsonEvent)
			if result == 2 {
				// send work to hangup queue
				nextTime, _ := status["next_time"].(string)
				t, _ := time.Parse(time.RFC3339, nextTime)
				status["otherRules"] = k
				sessionHangupQueue <- work{
					Event:         event,
					Rules:         rules,
					JsonEvent:     jsonEvent,
					SessionStatus: status,
					NextTime:      t,
				}
			}
		}(j)

	}
	wg.Wait()
}

func runSteps(event Event, rule Rule, jsonEvent map[string]interface{}) (int64, map[string]interface{}) {
	var checkOK bool
	var sessionStatus map[string]interface{}

	sessionID, err := cacheSessionTrigger(event, jsonEvent)
	if err != nil {
		return 0, sessionStatus
	}

	var ii int
	for ii = range rule.Steps {
		logging.Get().Debug().Int("index", ii).Str("name", rule.Name).Str("code", rule.Steps[ii].Code).Msg("MOZART_DEBUG - ruleStep")
		query, err := regoPreQueries.get(rule.Steps[ii].Code)
		if err != nil {
			logging.Get().Error().Err(err).Int("index", ii).Str("name", rule.Name).Str("code", rule.Steps[ii].Code).Msg("invalid rule step")
			return 0, sessionStatus
		}

		switch rule.Steps[ii].Type {
		case "check":
			checkOK, err = check(*query, sessionID)
			if err != nil {
				logging.Get().Error().Err(err).Int("index", ii).Str("name", rule.Name).Str("code", rule.Steps[ii].Code).Msg("check fails")
				return 0, sessionStatus
			}
			// check session status
			// return session status
			sessionStatus, ok := checkCacheSessionStatus(sessionID)
			if ok {
				sessionStatus["ruleStepIndex"] = ii
				return 2, sessionStatus
			}
			if !checkOK {
				logging.Get().Debug().Int("index", ii).Str("name", rule.Name).Str("code", rule.Steps[ii].Code).Msg("MOZART_DEBUG - check not ok")
				return 0, sessionStatus
			} else {
				logging.Get().Debug().Int("index", ii).Str("name", rule.Name).Str("code", rule.Steps[ii].Code).Msg("MOZART_DEBUG - check ok")
			}
		case "exec":
			err = exec(*query, sessionID)
			if err != nil {
				logging.Get().Error().Err(err).Int("index", ii).Str("name", rule.Name).Str("code", rule.Steps[ii].Code).Msg("exec fails")
				return 0, sessionStatus
			}
			logging.Get().Debug().Int("index", ii).Str("name", rule.Name).Str("code", rule.Steps[ii].Code).Msg("MOZART_DEBUG - exec ok")
		default:
		}
	}
	if ii == len(rule.Steps)-1 {
		return 1, sessionStatus
	}
	return 0, sessionStatus
}

func check(regoQ rego.PreparedEvalQuery, sessionID string) (bool, error) {
	ctx := context.Background()
	checkResult := false

	rs, err := regoQ.Eval(ctx, rego.EvalInput(map[string]interface{}{"session_id": sessionID}))
	if err != nil {
		return false, err
	}
	if len(rs) == 0 {
		//return false, errors.New("empty eval result")
		return false, nil
	}

	// cache expressions
	// expression.value 的第一项，约定为check的结果，bool类型
	// expression.value 的第二项，约定为返回数据，需要cache到session
	// 如果value不是list，则应该为check的结果，bool类型
	result, ok := rs[0].Expressions[0].Value.([]interface{})
	if ok {
		checkResult, _ = result[0].(bool)
		sc, _ := result[1].(string)
		if len(sc) != 0 {
			appendC := make(map[string]interface{})
			_ = json.Unmarshal([]byte(sc), &appendC)
			cache.Lock.Lock()
			for k, v := range appendC {
				cache.Sessions[sessionID][k] = v
			}
			cache.Lock.Unlock()
		}
	} else {
		checkResult = rs[0].Expressions[0].Value.(bool)
	}
	return checkResult, nil
}

func exec(regoQ rego.PreparedEvalQuery, sessionID string) error {
	ctx := context.Background()

	rs, err := regoQ.Eval(ctx, rego.EvalInput(map[string]interface{}{"session_id": sessionID}))
	if err != nil {
		return err
	}

	// todo: 如果没有任何的绑定，没有任何的返回，这里可能是 len(rs)==0
	if len(rs) == 0 {
		//return errors.New("empty eval result")
		return nil
	}

	cache.Lock.Lock()
	for k, v := range rs[0].Bindings {
		switch v.(type) {
		case map[string]interface{}:
			cache.Sessions[sessionID][k] = v.(map[string]interface{})
		default:
			cache.Sessions[sessionID][k] = v
		}
	}
	cache.Lock.Unlock()
	return nil
}

func cacheGlobal(event Event, jsonEvent map[string]interface{}) error {
	cache.Lock.Lock()
	defer cache.Lock.Unlock()

	// 缓存到全量event
	if events, ok := cache.Data[event.Name]; ok {
		// 按告警时间递增排序
		k := 0
		for i := len(events) - 1; i >= 0; i-- {
			if !event.Time.Before(events[i]["time"].(time.Time)) {
				k = i + 1
				break
			}
			if i == 0 && event.Time.Before(events[i]["time"].(time.Time)) {
				k = 0
				break
			}
		}
		ne := make([]map[string]interface{}, len(events)+1)
		if k == len(events) {
			ne = append(events, jsonEvent)
		} else {
			for i := 0; i < len(events); i++ {
				if i != k {
					j := i
					if i > k {
						j = i - 1
					}
					ne[i] = events[j]
				} else {
					ne[i] = jsonEvent
				}
			}
			ne[len(events)] = events[len(events)-1]
		}

		cache.Data[event.Name] = ne
	} else {
		cache.Data[event.Name] = []map[string]interface{}{jsonEvent}
	}

	return nil
}

func cacheSessionTrigger(event Event, jsonEvent map[string]interface{}) (string, error) {
	cache.Lock.Lock()
	defer cache.Lock.Unlock()

	// 缓存到当前session
	sessionID := strconv.Itoa(rand.Intn(99999999999))
	cache.Sessions[sessionID] = map[string]interface{}{
		"trigger":    jsonEvent,
		"event_time": event.Time.Format(time.RFC3339),
	}

	return sessionID, nil
}

func cacheSessionStatus(sessionID string, status map[string]interface{}) {
	cache.Lock.Lock()
	defer cache.Lock.Unlock()

	// 缓存到当前session
	cache.Sessions[sessionID] = map[string]interface{}{
		"status": status,
	}

}

func checkCacheSessionStatus(sessionID string) (map[string]interface{}, bool) {
	v, ok := checkCacheSession(sessionID, "status")
	if !ok {
		return nil, false
	}
	mv, ok := v.(map[string]interface{})
	return mv, ok
}

func checkCacheSession(sessionID string, key string) (interface{}, bool) {
	cache.Lock.Lock()
	defer cache.Lock.Unlock()

	value, ok := cache.Sessions[sessionID][key]
	return value, ok
}

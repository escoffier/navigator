package mozart

import (
	"context"
	"math/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	json "github.com/json-iterator/go"
	"github.com/open-policy-agent/opa/rego"

	"gitlab.com/security-rd/go-pkg/logging"
)

type jobArgs struct {
	e     *Engine
	Event Event
	Rules []Rule
}

func job(iArg interface{}) {

	args, _ := iArg.(jobArgs)
	event := args.Event
	e := args.e

	event.Time = event.Time.Local()

	bEvent, err := json.Marshal(event)
	if err != nil {
		logging.Get().Error().Err(err).Interface("event", event).Msg("input event not invalid json")
		return
	}
	jsonEvent := make(map[string]interface{})
	err = json.Unmarshal(bEvent, &jsonEvent)
	if err != nil {
		logging.Get().Error().Err(err).Interface("event", event).Msg("input event not invalid json")
		return
	}
	// 避免后续的时间格式转换，占用cpu时间
	jsonEvent["time"] = event.Time

	err = cacheGlobal(event, jsonEvent)
	if err != nil {
		logging.Get().Error().Err(err).Interface("event", event).Msg("cacheGlobal event fails")
	}

	rules, ok := e.Rules(e.GetActiveRulesVersion(), event.Name)
	if !ok {
		return
	}

	for k := range rules.rulesWithDefault {
		defaultRuleIndex := -1
		var succeedCount atomic.Int64
		wg := sync.WaitGroup{}
		for j := range rules.rulesWithDefault[k] {
			if !rules.rulesWithDefault[k][j].Enabled {
				continue
			}
			if rules.rulesWithDefault[k][j].Default.Enabled {
				defaultRuleIndex = j
				continue
			}

			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				succeed := runSteps(event, rules.rulesWithDefault[k][n], jsonEvent)
				succeedCount.Add(succeed)
			}(j)
		}
		wg.Wait()
		if succeedCount.Load() == 0 && defaultRuleIndex != -1 {
			// 其他分支全部失败，执行default分支
			runSteps(event, rules.rulesWithDefault[k][defaultRuleIndex], jsonEvent)
		}
	}

	wg := sync.WaitGroup{}
	for j := range rules.otherRules {
		if !rules.otherRules[j].Enabled {
			continue
		}
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			runSteps(event, rules.otherRules[k], jsonEvent)
		}(j)

	}
	wg.Wait()
}

func runSteps(event Event, rule Rule, jsonEvent map[string]interface{}) int64 {
	var checkOK bool

	sessionID, err := cacheSession(event, jsonEvent)
	if err != nil {
		return 0
	}

	var ii int
	for ii = range rule.Steps {
		query, err := regoPreQueries.get(rule.Steps[ii].Code)
		if err != nil {
			logging.Get().Error().Err(err).Str("step_code", rule.Steps[ii].Code).Msg("invalid rule step")
			return 0
		}

		switch rule.Steps[ii].Type {
		case "check":
			checkOK, err = check(*query, sessionID)
			if err != nil {
				logging.Get().Error().Err(err).Msg("check fails: " + strconv.Itoa(ii) + rule.Name + rule.Steps[ii].Code)
				return 0
			}
			if !checkOK {
				//logging.Get().Error().Err(err).Msg("check not ok: " + strconv.Itoa(ii) + rule.Name + rule.Steps[ii].Code)
				return 0
			}
		case "exec":
			err = exec(*query, sessionID)
			if err != nil {
				logging.Get().Error().Err(err).Msg("exec fails: " + strconv.Itoa(ii) + rule.Name + rule.Steps[ii].Code)
				return 0
			}
		default:
		}
	}
	if ii == len(rule.Steps)-1 {
		return 1
	}
	return 0
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

	// Do something with result.
	_, ok := rs[0].Expressions[0].Value.([]interface{})
	if ok {
		//checkResult, _ = result[0].(bool)
		//sc, _ := result[1].(string)
		//appendC := make(map[string]interface{})
		//_ = json.Unmarshal([]byte(sc), &appendC)
		//cache.Lock.Lock()
		//for k, v := range appendC {
		//	cache.Sessions[w.SessionID][k] = v
		//}
		//cache.Lock.Unlock()
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

func cacheSession(event Event, jsonEvent map[string]interface{}) (string, error) {
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

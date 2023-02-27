package mozart

import (
	"context"
	"strconv"
	"sync"
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

	Cache.Lock.Lock()
	// 缓存到全量event
	if events, ok := Cache.Data[event.Name]; ok {
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

		Cache.Data[event.Name] = ne
	} else {
		Cache.Data[event.Name] = []map[string]interface{}{jsonEvent}
	}

	// 缓存到当前session
	c := map[string]interface{}{
		"trigger":    jsonEvent,
		"event_time": event.Time.Format(time.RFC3339),
	}
	sessionID := sha256Hash(bEvent)
	Cache.Sessions[sessionID] = c
	Cache.Lock.Unlock()

	rules, ok := e.Rules(e.GetActiveRulesVersion(), event.Name)
	if !ok {
		return
	}

	wg := sync.WaitGroup{}
	for j := range rules {
		if !rules[j].Enabled {
			continue
		}

		wg.Add(1)
		go func(rule Rule) {
			defer wg.Done()
			var checkOK bool

			for i := range rule.Steps {
				query, err := regoPreQueries.get(rule.Steps[i].Code)
				if err != nil {
					logging.Get().Error().Err(err).Str("step_code", rule.Steps[i].Code).Msg("invalid rule step")
					return
				}

				switch rule.Steps[i].Type {
				case "check":
					checkOK, err = check(*query, sessionID)
					if err != nil {
						logging.Get().Error().Err(err).Msg("check fails: " + strconv.Itoa(i) + rule.Name + rule.Steps[i].Code)
						return
					}
					if !checkOK {
						return
					}
				case "exec":
					err = exec(*query, sessionID)
					if err != nil {
						logging.Get().Error().Err(err).Msg("exec fails: " + strconv.Itoa(i) + rule.Name + rule.Steps[i].Code)
						return
					}
				default:
				}
			}
		}(rules[j])
	}

	wg.Wait()
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
		//Cache.Lock.Lock()
		//for k, v := range appendC {
		//	Cache.Sessions[w.SessionID][k] = v
		//}
		//Cache.Lock.Unlock()
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

	Cache.Lock.Lock()
	for k, v := range rs[0].Bindings {
		switch v.(type) {
		case map[string]interface{}:
			Cache.Sessions[sessionID][k] = v.(map[string]interface{})
		default:
			Cache.Sessions[sessionID][k] = v
		}
	}
	Cache.Lock.Unlock()
	return nil
}

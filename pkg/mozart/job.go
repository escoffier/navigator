package mozart

import (
	"context"
	"errors"
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

type Worker struct {
	Cache map[string]interface{}
	deps  depOption
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
	if events, ok := Cache.Data[event.Name]; ok {
		Cache.Data[event.Name] = append(events, jsonEvent)
	} else {
		Cache.Data[event.Name] = []map[string]interface{}{jsonEvent}
	}
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

			eventM := make(map[string]interface{})
			be, _ := json.Marshal(event)
			_ = json.Unmarshal(be, &eventM)
			c := map[string]interface{}{
				"trigger":    eventM,
				"event_time": event.Time.Format(time.RFC3339),
			}

			worker := Worker{Cache: c, deps: e.deps}

			defer wg.Done()
			var checkOK bool
			for i := range rule.Steps {
				switch rule.Steps[i].Type {
				case "check":
					regoQuery, err := worker.configToRegoQuery(rule.Steps[i].Name, rule.Steps[i].Code)
					if err != nil {
						logging.Get().Error().Err(err).Str("stepName", rule.Steps[i].Name).Str("stepCode", rule.Steps[i].Code).Msg("configToRegoQuery fails")
						return
					}

					checkOK, err = worker.check(regoQuery)

					if err != nil {
						logging.Get().Error().Err(err).Msg("check fails: " + strconv.Itoa(i) + rule.Name + rule.Steps[i].Code)
						return
					}
					if !checkOK {
						//logging.Get().Info().Msg("check not ok: " + strconv.Itoa(i) + rule.Name + rule.Steps[i].Code)
						return
					}
					//logging.Get().Info().Msg("check ok: " + strconv.Itoa(i) + rule.Name + rule.Steps[i].Code)
				case "exec":
					regoQuery, err := worker.configToRegoQuery(rule.Steps[i].Name, rule.Steps[i].Code)
					if err != nil {
						logging.Get().Error().Err(err).Str("stepName", rule.Steps[i].Name).Str("stepCode", rule.Steps[i].Code).Msg("configToRegoQuery fails")
						return
					}
					err = worker.exec(regoQuery)

					if err != nil {
						logging.Get().Error().Err(err).Msg("exec fails: " + strconv.Itoa(i) + rule.Name + rule.Steps[i].Code)
						return
					}
					//logging.Get().Info().Msg("exec ok: " + strconv.Itoa(i) + rule.Name + rule.Steps[i].Code + event.Time.String())
				default:
				}
			}
		}(rules[j])
	}

	wg.Wait()
}

func (w *Worker) check(regoQ rego.PreparedEvalQuery) (bool, error) {
	ctx := context.Background()
	checkResult := false

	rs, err := regoQ.Eval(ctx)
	if err != nil {
		return false, err
	}
	if len(rs) == 0 {
		return false, errors.New("empty eval result")
	}

	// Do something with result.
	result, ok := rs[0].Expressions[0].Value.([]interface{})
	if ok {
		checkResult, _ = result[0].(bool)
		sc, _ := result[1].(string)
		appendC := make(map[string]interface{})
		_ = json.Unmarshal([]byte(sc), &appendC)
		for k, v := range appendC {
			w.Cache[k] = v
		}
	} else {
		checkResult = rs[0].Expressions[0].Value.(bool)
	}
	return checkResult, nil
}

func (w *Worker) exec(regoQ rego.PreparedEvalQuery) error {
	ctx := context.Background()

	rs, err := regoQ.Eval(ctx)
	if err != nil {
		return err
	}

	// todo: 如果没有任何的绑定，没有任何的返回，这里可能是 len(rs)==0
	if len(rs) == 0 {
		return errors.New("empty eval result")
	}

	m := make(map[string]interface{})
	for k, v := range rs[0].Bindings {
		sv := v.(string)
		err = json.Unmarshal([]byte(sv), &m)
		if err != nil {
			w.Cache[k] = v
		} else {
			w.Cache[k] = m
		}
	}
	return nil
}

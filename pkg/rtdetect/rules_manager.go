package rtdetect

import (
	"context"
	"errors"
	"runtime/debug"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type RulesManager struct {
	rulesVal            atomic.Value // map[string]*model.RuleFromYaml
	localDataVersionVal uint64       /// please read/write it by method

	consoleHost    string
	updateInterval time.Duration
}

func NewRulesManager(consoleAddr string, updateInterval time.Duration) *RulesManager {
	rm := RulesManager{
		consoleHost:    consoleAddr,
		updateInterval: updateInterval,
	}
	rm.setRules(make(map[string]*model.RuleFromYaml, 0))

	rm.loadRules(context.Background())
	rm.asyncLoop()

	return &rm
}

func (rm *RulesManager) rules() map[string]*model.RuleFromYaml {
	return rm.rulesVal.Load().(map[string]*model.RuleFromYaml)
}
func (rm *RulesManager) setRules(newRules map[string]*model.RuleFromYaml) {
	rm.rulesVal.Store(newRules)
}
func (rm *RulesManager) localDataVersion() uint64 {
	return atomic.LoadUint64(&rm.localDataVersionVal)
}
func (rm *RulesManager) setLocalDataVersion(v uint64) {
	atomic.StoreUint64(&rm.localDataVersionVal, v)
}

func (rm *RulesManager) GetRules() []*model.RuleFromYaml {
	rulesMap := rm.rules()
	rules := make([]*model.RuleFromYaml, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}
	return rules
}
func (rm *RulesManager) GetRule(ruleName string) (*model.RuleFromYaml, bool) {
	rulesMap := rm.rules()
	rule, exist := rulesMap[ruleName]
	return rule, exist
}

func (rm *RulesManager) loadRules(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("laodRules Panic: %v. stack: %s", r, debug.Stack())
		}
		err = errors.New("panic")
	}()

	data, err := dal.LoadAttackRules(ctx, rm.consoleHost, rm.localDataVersion(), 0)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "error loading attack rules. host: %s. dataVer: %d", rm.consoleHost, rm.localDataVersion)
		return err
	}

	if !data.DataChanged {
		return nil
	}

	newRules := make(map[string]*model.RuleFromYaml, len(data.AttackRules))
	for _, rule := range data.AttackRules {
		newRules[rule.Rule] = rule
	}
	rm.setRules(newRules)
	rm.setLocalDataVersion(uint64(data.LatestDataVersion))

	return nil
}

func (rm *RulesManager) asyncLoop() {
	go func() {
		ticker := time.NewTicker(rm.updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rm.loadRules(context.Background())
			}
		}
	}()
}

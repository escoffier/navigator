package echelper

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
)

type RulesManager struct {
	rulesVal atomic.Value // map[string]*model.EvtCenterRule

	rdb      *databases.RDBInstance
	interval time.Duration
}

func NewRulesManager(rdb *databases.RDBInstance, interval time.Duration) *RulesManager {
	r := RulesManager{
		rdb:      rdb,
		interval: interval,
	}
	r.loadRules()
	r.asyncLoop()

	return &r
}
func (rm *RulesManager) loadRules() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()

	tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rules := make([]*model.EvtCenterRule, 0, 200)

	err := rm.rdb.Get().WithContext(tctx).Model(&model.EvtCenterRule{}).Where("status = ?", 0).Find(&rules).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("load event centers rules error")
	} else {
		rulesMap := make(map[string]*model.EvtCenterRule, len(rules))
		for _, r := range rules {
			rulesMap[getRuleKey(r.Module, r.Category, r.Name)] = r
		}
		rm.rulesVal.Store(rulesMap)
	}
}

func (rm *RulesManager) GetRule(module, category, ruleName string) (*model.EvtCenterRule, bool) {
	key := getRuleKey(module, category, ruleName)
	m := rm.getRules()
	if m == nil {
		return nil, false
	}
	r, ok := m[key]
	return r, ok
}

func getRuleKey(module, category, ruleName string) string {
	return fmt.Sprintf("%s/%s/%s", module, category, ruleName)
}

func (rm *RulesManager) getRules() map[string]*model.EvtCenterRule {
	return rm.rulesVal.Load().(map[string]*model.EvtCenterRule)
}
func (rm *RulesManager) asyncLoop() {
	go func() {
		ticker := time.NewTicker(rm.interval)
		defer ticker.Stop()

		for range ticker.C {
			rm.loadRules()
		}
	}()
}

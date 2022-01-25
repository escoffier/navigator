package rtdetect

import (
	"context"
	"errors"
	"math/rand"
	"runtime/debug"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type RulesManager struct {
	rulesVal            atomic.Value // map[string]string
	localDataVersionVal uint64       /// please read/write it by method

	consoleHost    string
	updateInterval time.Duration
}

func NewRulesManager(consoleAddr string, updateInterval time.Duration) *RulesManager {
	rm := RulesManager{
		consoleHost:    consoleAddr,
		updateInterval: updateInterval,
	}
	rm.setRules(make(map[string]string, 0))

	rm.loadRules(context.Background())
	rm.asyncLoop()

	return &rm
}

func (rm *RulesManager) rules() map[string]string {
	return rm.rulesVal.Load().(map[string]string)
}
func (rm *RulesManager) setRules(newRules map[string]string) {
	rm.rulesVal.Store(newRules)
}
func (rm *RulesManager) localDataVersion() uint64 {
	return atomic.LoadUint64(&rm.localDataVersionVal)
}
func (rm *RulesManager) setLocalDataVersion(v uint64) {
	atomic.StoreUint64(&rm.localDataVersionVal, v)
}

func (rm *RulesManager) GetCategoryOfRule(ruleName string) (string, bool) {
	rulesMap := rm.rules()
	category, exist := rulesMap[ruleName]
	return category, exist
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

	newRules := make(map[string]string, len(data.AttackRules))
	for _, rule := range data.AttackRules {
		newRules[rule.Rule] = rule.Category
	}
	rm.setRules(newRules)
	rm.setLocalDataVersion(uint64(data.LatestDataVersion))

	return nil
}

func (rm *RulesManager) asyncLoop() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		time.Sleep(time.Duration(rand.Int63n(rm.updateInterval.Nanoseconds())))
		ticker := time.NewTicker(rm.updateInterval)
		defer ticker.Stop()

		for range ticker.C {
			rm.loadRules(context.Background())
		}
	}()
}

package attck

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"time"
)

func (h *ATTCKHandler) GetRuleTemplates(ctx context.Context, version1 int, keyword string, lang lang.LanguageType) ([]*model.RuleTemplate, error) {
	return h.sherlockClient.GetRuleTemplates(ctx, version1, nil, &keyword, lang)
}

func (h *ATTCKHandler) CreateRuleTemplates(ctx context.Context, version1 int, name, description, creator string, lang lang.LanguageType) error {

	openedRules := make([]string, 0)
	rules, ok := h.rules[uint16(version1)]
	if !ok {
		return errors.New("no such version1 rules")
	}
	rules.cacheLock.Lock()
	for i := range rules.items {
		if !rules.items[i].disabled {
			openedRules = append(openedRules, rules.items[i].name)
		}
	}
	rules.cacheLock.Unlock()

	return h.sherlockClient.CreateRuleTemplates(ctx, version1, name, description, creator, openedRules, lang)
}

func (h *ATTCKHandler) DeleteRuleTemplates(ctx context.Context, version1, id int, lang lang.LanguageType) error {
	return h.sherlockClient.DeleteRuleTemplates(ctx, version1, id, lang)
}

func (h *ATTCKHandler) GetRuleTemplatesRules(ctx context.Context, version1, id int, keyword *string, ruleType *[]string, urgency *[]bool, severity *[]int, _switch *[]bool, lang lang.LanguageType) ([]*model.RuleTemplateRule, error) {
	return h.sherlockClient.GetRuleTemplatesRules(ctx, version1, id, keyword, ruleType, urgency, severity, _switch, lang)
}

func (h *ATTCKHandler) ApplyRuleTemplates(ctx context.Context, version1, id int, lang lang.LanguageType, updater string) error {
	ruleTemplates, err := h.sherlockClient.GetRuleTemplates(ctx, version1, &id, nil, lang)
	if err != nil {
		return err
	}
	if len(ruleTemplates) != 1 {
		return fmt.Errorf("rule templates count not %d", len(ruleTemplates))
	}
	ruleTemplate := ruleTemplates[0]

	templateRules, err := h.sherlockClient.GetRuleTemplatesRules(ctx, version1, id, nil, nil, nil, nil, nil, lang)
	if err != nil {
		return err
	}
	vRules, ok := h.rules[uint16(version1)]
	if !ok {
		return ErrInvalidRulesVersion1
	}

	openedRuleNames := make([]string, 0)
	openedRules := make([]model.RuleSwitch, 0)
	closedRules := make([]model.RuleSwitch, 0)
	for i := range templateRules {
		if templateRules[i].Switch {
			openedRuleNames = append(openedRuleNames, templateRules[i].Key)
			openedRules = append(openedRules, model.RuleSwitch{
				Version1:  version1,
				Name:      templateRules[i].Key,
				Switch:    templateRules[i].Switch,
				Updater:   updater,
				UpdatedAt: time.Now().UnixMilli(),
			})
		} else {
			closedRules = append(closedRules, model.RuleSwitch{
				Version1:  version1,
				Name:      templateRules[i].Key,
				Switch:    templateRules[i].Switch,
				Updater:   updater,
				UpdatedAt: time.Now().UnixMilli(),
			})
		}
		// 理论上不存在items中不存在的key，因为更新规则的时候同步更新了 h.rules 和 规则模板。
		// fixme: 这里有bug，暂时没看出逻辑的问题。先处理panic
		if vRules.items != nil {
			if r, ok := vRules.items[templateRules[i].Key]; ok {
				if r != nil {
					vRules.items[templateRules[i].Key].disabled = !templateRules[i].Switch
				}
			}
		}
	}
	if err := dal.UpdateRuleSwitches(ctx, h.db.Get(), openedRules, closedRules, uint16(version1)); err != nil {
		return err
	}

	// 把内置模板的配置替换为具体的规则
	ruleTemplate.Config.Type = "switch"
	ruleTemplate.Config.Opened = openedRuleNames
	if err := dal.CreateRuleTemplateApplyHistory(ctx, h.db.Get(), uint16(version1), *ruleTemplate, updater); err != nil {
		return err
	}

	vRules.sortedItems = makeSortedItems(vRules.items)
	vRules.onlineOffset++
	h.rules[uint16(version1)] = vRules

	return nil
}

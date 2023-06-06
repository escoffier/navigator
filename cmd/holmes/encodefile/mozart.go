package main

import (
	"context"
	"encoding/json"
	"errors"
	"gitlab.com/security-rd/go-pkg/util"
	"math/rand"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/mozart"
)

func mozart2UserRule(ctx context.Context, ruleBytes []byte) ([]model.UserRuleYaml, map[string][]model.UserRuleYaml, error) {
	type rulesMapItem struct {
		rule  model.UserRuleYaml
		index int
	}

	data := make([]model.MozartYaml, 0)
	rules := make([]model.UserRuleYaml, 0)
	rulesMap := make(map[string]rulesMapItem)
	index := 0

	err := yaml.Unmarshal(ruleBytes, &data)
	if err != nil {
		return nil, nil, err
	}

	mozartUsersMap := make(map[string][]model.UserRuleYaml)

	var mozartMarco []model.MozartYaml
	for i := range data {
		if !mozart.IsMozartMarco(data[i]) {
			continue
		}
		mozartMarco = append(mozartMarco, data[i])
	}

	// 规则数据
	for i := range data {
		if !mozart.IsMozartOrRelatedRule(data[i]) {
			continue
		}

		if data[i].Key == "" {
			bd, _ := json.Marshal(data[i])
			logging.Get().Warn().Str("Key", data[i].Key).Str("data", string(bd)).Msg("invalid rule key")
			continue
		}

		// 生成替换值
		values := map[string]interface{}{"0": map[string]interface{}{}}
		switches := map[string]interface{}{"0": map[string]interface{}{}}
		for k := range data[i].Steps {
			innerValues, innerSwitches, err := mozart.ExtractValues(ctx, data[i].Steps[k], mozartMarco, "0")
			if err != nil {
				return nil, nil, err
			}
			for ik, iv := range innerValues {
				values["0"].(map[string]interface{})[ik] = iv
			}
			for ik, iv := range innerSwitches {
				switches["0"].(map[string]interface{})[ik] = iv
			}
		}

		// 生成分支
		stepsTotal := make([]model.StepMore, 0)
		var stepsMatrix []model.StepMore
		for k := range data[i].Steps {
			stepsMatrix, err = configStep2MozartStep(ctx, data[i].Steps[k], mozartMarco, "0")
			if err != nil {
				return nil, nil, err
			}
			if len(stepsMatrix) == 0 {
				continue
			}
			newStepsTotal := make([]model.StepMore, 0)
			if len(stepsTotal) == 0 {
				newStepsTotal = stepsMatrix
			} else {
				for m := 0; m < len(stepsMatrix); m++ {
					nst := make([]model.StepMore, len(stepsTotal))
					for n := 0; n < len(stepsTotal); n++ {
						nst[n].Steps = append(stepsTotal[n].Steps, stepsMatrix[m].Steps...)
						nst[n].Key = correctKey(stepsTotal[n].Key, stepsMatrix[m].Key)
						nst[n].Default = defaultOR(stepsTotal[n].Default, stepsMatrix[m].Default) // todo: 分支嵌套分支，有问题
					}
					newStepsTotal = append(newStepsTotal, nst...)
				}
			}
			stepsTotal = newStepsTotal
		}

		// 没有配置steps，常规规则，直接生成rule
		if len(stepsTotal) == 0 {
			ruleEnName, err := convertValuesByKey(data[i].Info.Name.En, "0", values)
			if err != nil {
				continue
			}
			info, err := convertInfoByKey(data[i].Info, "0", values)
			if err != nil {
				continue
			}

			ruleItem, ok := rulesMap[ruleEnName]
			rule := ruleItem.rule
			if !ok {
				rule = model.UserRuleYaml{
					Key:       data[i].Key,
					Name:      ruleEnName,
					Enabled:   !data[i].Disabled,
					Hid:       data[i].Hid,
					Type:      userRuleType("", data[i].Info.Tags),
					Condition: data[i].Condition, // 业务上不存在多种条件触发同一规则的情况
					Info:      info,

					MozartParts: []model.MozartRulePart{
						{
							Trigger: model.Trigger{Event: map[string]interface{}{
								"name": data[i].Key,
							}},
							Steps:   addSendSignalSteps(ctx, []model.Step{}, ruleEnName),
							Type:    mozartRuleType(data[i].Info.Tags),
							Default: model.BranchDefault{},
						},
					},
					MozartYamls: []model.MozartYaml{data[i]},
				}
			} else {
				rule.Enabled = rule.Enabled || !data[i].Disabled // 如果多个分支的输出规则是同一个，则只要有一个分支开启 -> 该规则开启
				rule.Type = userRuleType(rule.Type, data[i].Info.Tags)
				rule.MozartParts = append(rule.MozartParts, model.MozartRulePart{
					Trigger: model.Trigger{Event: map[string]interface{}{
						"name": data[i].Key,
					}},
					Steps:   addSendSignalSteps(ctx, []model.Step{}, ruleEnName),
					Type:    mozartRuleType(data[i].Info.Tags),
					Default: model.BranchDefault{},
				})
				rule.MozartYamls = append(rule.MozartYamls, data[i])
			}
			if mozart.IsMozartRelatedRule(data[i]) && !ok {
				rule.MozartParts = nil
			}
			rulesMap[ruleEnName] = rulesMapItem{
				rule:  rule,
				index: index,
			}
			index++

			mozartUsersMap[data[i].Key] = []model.UserRuleYaml{rule}
		}

		// 替换赋值并生成rule
		for ii := range stepsTotal {
			relateds := make([]model.Related, 0)
			for jj := range stepsTotal[ii].Steps {
				if stepsTotal[ii].Steps[jj].Name == "checkRelatedExists" { // 确认关联规则
					if params, ok := stepsTotal[ii].Steps[jj].OriginParams.([]interface{}); ok {
						relateds = append(relateds, model.Related{RuleName: params[0].(string)})
					}
				}
				if stepsTotal[ii].Steps[jj].Name == "checkRegexMatch" { // 正则里有太多语法，和我们的替换赋值有冲突
					continue
				}
				stepsTotal[ii].Steps[jj].Code, err = convertValuesByKey(stepsTotal[ii].Steps[jj].Code, stepsTotal[ii].Key, values)
				if err != nil {
					continue
				}
			}
			ruleEnName, err := convertValuesByKey(data[i].Info.Name.En, stepsTotal[ii].Key, values)
			if err != nil {
				continue
			}
			info, err := convertInfoByKey(data[i].Info, stepsTotal[ii].Key, values)
			if err != nil {
				continue
			}

			enabled, err := userRuleEnabled(stepsTotal[ii], !data[i].Disabled, switches)
			if err != nil {
				logging.Get().Error().Err(err).Msg("checkSwitchesByKey fails")
				continue
			}

			ruleItem, ok := rulesMap[ruleEnName]
			rule := ruleItem.rule
			if !ok {
				rule = model.UserRuleYaml{
					Key:       data[i].Key,
					Name:      ruleEnName,
					Enabled:   enabled,
					Hid:       data[i].Hid,
					Type:      userRuleType("", data[i].Info.Tags),
					Condition: data[i].Condition, // 业务上不存在多种条件触发同一规则的情况
					Info:      info,

					MozartParts: []model.MozartRulePart{
						{
							Trigger: model.Trigger{Event: map[string]interface{}{
								"name": data[i].Key,
							}},
							Relateds: relateds,
							Steps:    addSendSignalSteps(ctx, stepsTotal[ii].Steps, ruleEnName),
							Type:     mozartRuleType(data[i].Info.Tags),
							Default:  stepsTotal[ii].Default,
						},
					},
					MozartYamls: []model.MozartYaml{data[i]},
				}
			} else {
				rule.Enabled = rule.Enabled || enabled // 如果多个分支的输出规则是同一个，则只要有一个分支开启 -> 该规则开启
				rule.Type = userRuleType(rule.Type, data[i].Info.Tags)
				rule.MozartParts = append(rule.MozartParts, model.MozartRulePart{
					Trigger: model.Trigger{Event: map[string]interface{}{
						"name": data[i].Key,
					}},
					Relateds: relateds,
					Steps:    addSendSignalSteps(ctx, stepsTotal[ii].Steps, ruleEnName),
					Type:     mozartRuleType(data[i].Info.Tags),
					Default:  stepsTotal[ii].Default,
				})
				rule.MozartYamls = append(rule.MozartYamls, data[i])
			}
			if mozart.IsMozartRelatedRule(data[i]) && !ok {
				rule.MozartParts = nil
			}
			rulesMap[ruleEnName] = rulesMapItem{
				rule:  rule,
				index: index,
			}
			index++

			if userRules, ok := mozartUsersMap[data[i].Key]; ok {
				mozartUsersMap[data[i].Key] = append(userRules, rule)
			} else {
				mozartUsersMap[data[i].Key] = []model.UserRuleYaml{rule}
			}

		}
	}

	ruleItems := make([]rulesMapItem, 0)
	for _, ruleItem := range rulesMap {
		ruleItems = append(ruleItems, ruleItem)
	}

	sort.Slice(ruleItems, func(i, j int) bool {
		return ruleItems[i].index < ruleItems[j].index
	})

	for i := range ruleItems {
		rules = append(rules, ruleItems[i].rule)
	}

	// 非规则数据
	for i := range data {
		if mozart.IsMozartOrRelatedRule(data[i]) {
			continue
		}

		if mozart.IsMozartMarco(data[i]) {
			rules = append(rules, model.UserRuleYaml{
				Key:      data[i].Key,
				Type:     data[i].Type,
				Branches: data[i].Branches,
			})
		}

		if mozart.IsMarco(data[i]) {
			rules = append(rules, model.UserRuleYaml{
				Macro:     data[i].Macro,
				Condition: data[i].Condition,
				List:      data[i].List,
				Items:     data[i].Items,
			})
		}
	}

	return rules, mozartUsersMap, nil
}

func userRuleType(other string, tags []string) string {
	if other == "mozart_rule" {
		return "mozart_rule"
	}

	if util.ContainsString(tags, "related") {
		return "mozart_related_rule"
	}
	return "mozart_rule"
}

func configStep2MozartStep(ctx context.Context, configStep model.ConfigMozartStep, mozartMarco []model.MozartYaml, key string) ([]model.StepMore, error) {
	var stepMatrix []model.StepMore
	var err error

	switch configStep.Name {
	// 纯表达式
	case "checkExpression":
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsCheckExpression(configStep.Params.(string)).RCode(), configStep)}, Key: key}}
	case "execExpression":
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsExecExpression(configStep.Params.(string)).RCode(), configStep)}, Key: key}}

	// 内置函数
	case "checkValue":
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsCheckValue(configStep.Params.([]interface{})).RCode(), configStep)}, Key: key}}
	case "checkValueInList":
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsCheckValueInList(configStep.Params.([]interface{})).RCode(), configStep)}, Key: key}}
	case "checkRelatedExists":
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsCheckRelatedExists(configStep.Params.([]interface{})).RCode(), configStep)}, Key: key}}
	case "checkRuleRecentCount":
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsCheckRuleRecentCount(configStep.Params.([]interface{})).RCode(), configStep)}, Key: key}}
	case "checkRegexMatch":
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsCheckRegexMatch(configStep.Params.([]interface{})).RCode(), configStep)}, Key: key}}
	case "execDefineValue":
		p := configStep.Params.(map[interface{}]interface{})
		mp := make(map[string]interface{}, len(p))
		for k, v := range p {
			mp[k.(string)] = v
		}
		configStep.Params = mp
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsExecDefineValue(mp).RCode(), configStep)}, Key: key}}
	case "execGenerateSignal":
		p := configStep.Params.(map[interface{}]interface{})
		mp := make(map[string]interface{}, len(p))
		for k, v := range p {
			mp[k.(string)] = v
		}
		configStep.Params = mp
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsExecGenerateSignal(mp).RCode(), configStep)}, Key: key}}
	case "execSendPalace":
		stepMatrix = []model.StepMore{{Steps: []model.Step{simpleStep(mozart.ConfigMozartStepParamsExecSendPalace(configStep.Params.(string)).RCode(), configStep)}, Key: key}}

	case "branches":
		var innerBranchStepMatrix []model.StepMore
		branchName := strings.TrimPrefix(configStep.Params.(string), model.MarcoPrefix)
		branchID := branchName + strconv.Itoa(rand.Intn(99999999999))
		foundBranchMarco := false
		for i := range mozartMarco {
			if mozartMarco[i].Key != branchName {
				continue
			}
			foundBranchMarco = true
			for j := range mozartMarco[i].Branches {
				//if !mozartMarco[i].Branches[j].Enabled && !mozartMarco[i].Branches[j].Default {
				//	continue
				//}
				branchMatrix := make([]model.StepMore, 0)
				branchKey := key + "-" + strconv.Itoa(j)

				for k := range mozartMarco[i].Branches[j].Steps {
					innerBranchStepMatrix, err = configStep2MozartStep(ctx, mozartMarco[i].Branches[j].Steps[k], mozartMarco, branchKey)
					if err != nil {
						return nil, err
					}
					if len(innerBranchStepMatrix) == 0 { // defineValue等无需运行的step
						continue
					}
					if len(innerBranchStepMatrix) == 1 && len(innerBranchStepMatrix[0].Steps) == 1 { // basic simple step
						if len(branchMatrix) == 0 { // 长度为0，初始化
							branchMatrix = append(branchMatrix, innerBranchStepMatrix[0])
						} else { // 已有多个分支，将当前的simple step加入已有的分支尾端
							for m := range branchMatrix {
								branchMatrix[m].Steps = append(branchMatrix[m].Steps, innerBranchStepMatrix[0].Steps[0])
								branchMatrix[m].Key = correctKey(branchMatrix[m].Key, innerBranchStepMatrix[0].Key)
							}
						}
					} else { // embedded branches
						newStepsTotal := make([]model.StepMore, 0)
						if len(branchMatrix) == 0 {
							newStepsTotal = innerBranchStepMatrix
						} else {
							for m := 0; m < len(innerBranchStepMatrix); m++ {
								nst := make([]model.StepMore, len(branchMatrix))
								for n := 0; n < len(branchMatrix); n++ {
									nst[n].Steps = append(branchMatrix[n].Steps, innerBranchStepMatrix[m].Steps...)
									nst[n].Key = correctKey(branchMatrix[n].Key, innerBranchStepMatrix[m].Key)
								}
								newStepsTotal = append(newStepsTotal, nst...)
							}
						}
						branchMatrix = newStepsTotal
					}
				}
				for k := range branchMatrix {
					branchMatrix[k].Default.ID = branchID
					branchMatrix[k].Default.RunType = mozartMarco[i].Type
					if mozartMarco[i].Branches[j].Default {
						_true := true
						branchMatrix[k].Default.Enabled = &_true
					} else {
						_false := false
						branchMatrix[k].Default.Enabled = &_false
					}
				}
				stepMatrix = append(stepMatrix, branchMatrix...)
			}
		}
		if !foundBranchMarco {
			return stepMatrix, errors.New("no valid branch marco: " + branchName)
		}
	case "defineValue":
		//p := configStep.Params.(map[interface{}]interface{})
		//for k, v := range p {
		//	values[k.(string)] = v
		//}
	default:
		err = errors.New("no match step name")
		logging.Get().Error().Err(err).Str("stepName", configStep.Name).Msg("no match step name")
		return stepMatrix, err
	}

	return stepMatrix, nil
}

func simpleStep(code string, config model.ConfigMozartStep) model.Step {
	step := model.Step{Code: code}
	step.Name = config.Name
	if step.Name == "branches" {
		step.Type = "branches"
	} else if strings.HasPrefix(step.Name, "check") {
		step.Type = "check"
	} else {
		step.Type = "exec"
	}
	step.OriginParams = config.Params
	return step
}

func correctKey(k1, k2 string) string {
	if len(k1) > len(k2) {
		return k1
	}
	return k2
}

func defaultOR(a, b model.BranchDefault) model.BranchDefault {
	if b.Enabled != nil && a.Enabled == nil {
		return b
	}
	if b.Enabled == nil && a.Enabled != nil {
		return a
	}
	if b.Enabled == nil && a.Enabled == nil {
		return a
	}
	if *b.Enabled {
		return b
	} else {
		return a
	}
}

func convertValuesByKey(format string, key string, values map[string]interface{}) (string, error) {
	var err error
	var ok bool

	keyElems := strings.Split(key, "-")
	keys := make([]string, len(keyElems))
	for i := range keyElems {
		keys[i] = strings.Join(keyElems[:i+1], "-")
	}

	originVs := values
	keyValues := make([]map[string]interface{}, 0)
	for j := range keys {
		vs := make(map[string]interface{})
		originVs, ok = originVs[keys[j]].(map[string]interface{})
		if !ok {
			break
		}
		for k, v := range originVs {
			if mozart.CheckKey(k) {
				continue
			}
			vs[k] = v
		}
		keyValues = append(keyValues, vs)
	}

	var iFormat interface{}
	iFormat = format
	for k := len(keyValues) - 1; k >= 0; k-- {
		iFormat, err = mozart.TemplateFormat(iFormat, keyValues[k])
		if err != nil {
			// 由于可能存在运行过程中的format，所以此处对于未完成的参数保持开放态度。。
			continue
		}
	}

	return iFormat.(string), nil
}

func convertInfoByKey(info model.ConfigMozartInfoV3, key string, values map[string]interface{}) (model.ConfigMozartInfoV3, error) {
	newInfo := info
	newNameEn, err := convertValuesByKey(info.Name.En, key, values)
	if err != nil {
		return newInfo, err
	}
	newNameZh, err := convertValuesByKey(info.Name.Zh, key, values)
	if err != nil {
		return newInfo, err
	}
	newDescEn, err := convertValuesByKey(info.Desc.En, key, values)
	if err != nil {
		return newInfo, err
	}
	newDescZh, err := convertValuesByKey(info.Desc.Zh, key, values)
	if err != nil {
		return newInfo, err
	}
	newSuggEn, err := convertValuesByKey(info.Suggestion.En, key, values)
	if err != nil {
		return newInfo, err
	}
	newSuggZh, err := convertValuesByKey(info.Suggestion.Zh, key, values)
	if err != nil {
		return newInfo, err
	}
	newInfo.Name.En = newNameEn
	newInfo.Name.Zh = newNameZh
	newInfo.Desc.En = newDescEn
	newInfo.Desc.Zh = newDescZh
	newInfo.Suggestion.En = newSuggEn
	newInfo.Suggestion.Zh = newSuggZh
	return newInfo, nil
}

func userRuleEnabled(stepsTotal model.StepMore, mozartRuleEnabled bool, switches map[string]interface{}) (bool, error) {
	var enabled bool
	var err error
	// 不存在分支，直接使用mozart开关
	if stepsTotal.Key == "0" && len(switches) == 1 {
		enabled = mozartRuleEnabled
	} else {
		// 存在分支，使用分支的开关
		enabled, err = checkSwitchesByKey(stepsTotal.Key, switches)
		if err != nil {
			logging.Get().Error().Err(err).Msg("checkSwitchesByKey fails")
			return false, err
		}
	}
	return enabled, nil
}

func checkSwitchesByKey(key string, switches map[string]interface{}) (bool, error) {
	for k, v := range switches {
		if k == key {
			vm, ok := v.(map[string]interface{})
			if ok {
				enabled, ok := vm["enabled"].(bool)
				if ok {
					return enabled, nil
				}
			}
			return false, nil
		}
		if mozart.CheckKey(k) && strings.HasPrefix(key, k) {
			r, e := checkSwitchesByKey(key, v.(map[string]interface{}))
			if e == nil {
				return r, nil
			}
		}
	}
	return false, errors.New("no such key")
}

func mozartRuleType(tags []string) string {
	for i := range tags {
		if tags[i] == "related" {
			return "mozart_related"
		}
	}
	return "mozart"
}

func addSendSignalSteps(ctx context.Context, steps []model.Step, rule string) []model.Step {

	// 没有配置 生成告警 和 发送事件中心 step，补全这两个 step
	if len(steps) == 0 || steps[len(steps)-1].Name != "execGenerateSignal" {
		steps = append(steps, newExecGenerateSignalStep(ctx, rule))
		steps = append(steps, newExecSendPalace(ctx))
	}

	// 只配置了 生成告警 step，补全 发送事件中心 step
	if steps[len(steps)-1].Name == "execGenerateSignal" {
		steps = append(steps, newExecSendPalace(ctx))
	}

	// 已经配置 发送事件中心 step，直接返回
	if steps[len(steps)-1].Name == "execSendPalace" {
		return steps
	}

	return steps
}

func newExecGenerateSignalStep(ctx context.Context, rule string) model.Step {
	step := model.Step{}
	mp := make(map[string]interface{})
	mp["rule"] = rule
	step.Code = mozart.ConfigMozartStepParamsExecGenerateSignal(mp).RCode()
	step.Name = "execGenerateSignal"
	step.Type = "exec"
	step.OriginParams = mp
	return step
}

func newExecSendPalace(ctx context.Context) model.Step {
	step := model.Step{}
	step.Code = mozart.ConfigMozartStepParamsExecSendPalace("").RCode()
	step.Name = "execSendPalace"
	step.Type = "exec"
	step.OriginParams = ""
	return step
}

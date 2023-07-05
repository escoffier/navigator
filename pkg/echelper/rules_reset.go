package echelper

import (
	"context"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mozartcommon"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	gpModel "gitlab.com/security-rd/go-pkg/model"
	"gopkg.in/yaml.v2"
)

const (
	module   = "ContainerSecurity"
	moduleZh = "容器安全"
)

func SendRulesToEventCenterV3(ctx context.Context, cli *SherlockClient, rulesData []byte, version string) error {

	var rules = make(map[string][]*PalaceRule, 3)

	// v3.x版本基于mozart规则，重新定义了规则yaml
	var fDataRules []gpModel.UserRuleYaml
	err := yaml.Unmarshal(rulesData, &fDataRules)
	if err != nil {
		return err
	}

	for i := range fDataRules {

		if fDataRules[i].Type == "mozart_rule" { // mozart rule
			var hThreats uint8
			var rule *PalaceRule

			ruleEnName := fDataRules[i].Info.Name.En
			if ruleEnName == "" {
				continue
			}
			ruleZhName := fDataRules[i].Info.Name.Zh

			category, categoryZh := mozartcommon.CategoryFromTags(fDataRules[i].Info.Tags)
			descriptionZh := fDataRules[i].Info.Desc.Zh
			descriptionEn := fDataRules[i].Info.Desc.En

			priority := fDataRules[i].Info.Priority
			ruleType := fDataRules[i].Info.RuleType
			ruleTypeZh := model.TranslateRuleType(ruleType)
			if fDataRules[i].Info.Urgency {
				hThreats = 1
			}
			suggestionZh := fDataRules[i].Info.Suggestion.Zh
			suggestionEn := fDataRules[i].Info.Suggestion.En
			tags := Tags(fDataRules[i].Info.Tags)
			// 增加mozart规则
			rule = generateRule(category, categoryZh, ruleEnName, ruleZhName, descriptionEn, descriptionZh, priority, ruleType, ruleTypeZh, "", hThreats, suggestionEn, suggestionZh, tags)
			rules[rule.Category] = append(rules[rule.Category], rule)
		}
	}

	for category, cRules := range rules {
		err := cli.ResetCategoryRules(ctx, category, cRules, version)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("reset category %s rules error", category)
			return err
		}
	}
	return nil
}

func SendRulesToEventCenter(ctx context.Context, cli *SherlockClient, rulesData []byte, version string) error {

	var rules = make(map[string][]*PalaceRule, 3)

	var fDataRules []model.RuleFromYaml
	err := yaml.Unmarshal(rulesData, &fDataRules)
	if err != nil {
		return err
	}

	var mozartMarco []model.ConfigMozartMarco
	for i := range fDataRules {
		if len(fDataRules[i].MozartMarco) == 0 {
			continue
		}
		mozartMarco = fDataRules[i].MozartMarco
		break
	}

	for _, item := range fDataRules {
		if (len(item.Rule) == 0 || len(item.Priority) == 0) && len(item.Mozart) == 0 {
			continue
		}
		if item.Category == "" {
			item.Category = "ATT&CK"
		}

		// 只是关联规则，不应上报，跳过
		if !util.ContainsString(item.Tags, "triggered") && util.ContainsString(item.Tags, "related") {
			continue
		}
		// 触发规则严重级别较低，不应上报，跳过
		if util.ContainsString(item.Tags, "triggered") && !rtdetect.ComparePriority(item.Priority, "ERROR") {
			continue
		}

		var category string
		var categoryZh string
		var ruleName string
		var descriptionEn string
		var descriptionZh string
		var priority string
		var ruleType string
		var ruleTypeZh string
		var ruleTypeEn string
		var hid string
		var hThreats uint8

		var rule *PalaceRule

		if len(item.Mozart) != 0 {
			for i := range item.Mozart {
				category = "ATT&CK"
				categoryZh = "ATT&CK"
				values := map[string]interface{}{"0": map[string]interface{}{}}
				for j := range item.Mozart[i].Steps {
					if item.Mozart[i].Steps[j].Name == "execGenerateSignal" {
						params, _ := item.Mozart[i].Steps[j].Params.(map[interface{}]interface{})
						for k, v := range params {
							if k.(string) == "rule" {
								ruleName = v.(string)
							}
						}
					}
					innerValues, _, err := mozartcommon.ExtractValues(context.Background(), item.Mozart[i].Steps[j], mozartcommon.MozartMarcoV2ToV3(mozartMarco), "0")
					if err != nil {
						return err
					}
					for ik, iv := range innerValues {
						values["0"].(map[string]interface{})[ik] = iv
					}
				}
				if ruleName == "" {
					continue
				}
				flatValues := mozartcommon.FlatValues(values)
				if len(flatValues) == 0 {
					flatValues = []map[string]interface{}{{}} // 无变量赋值，使用空配置
				} else if mozartcommon.CheckDefaultFormatValue(ruleName) { // 存在默认值
					flatValues = append(flatValues, map[string]interface{}{})
				}
				for j := range flatValues {
					iDescZh, err := mozartcommon.TemplateFormat(item.Mozart[i].Info.Desc.Zh, flatValues[j])
					if err != nil {
						return err
					}
					iDescEn, err := mozartcommon.TemplateFormat(item.Mozart[i].Info.Desc.En, flatValues[j])
					if err != nil {
						return err
					}
					iRuleEnName, err := mozartcommon.TemplateFormat(ruleName, flatValues[j])
					if err != nil {
						return err
					}
					ruleZhName := iDescZh
					iSuggestionZh, err := mozartcommon.TemplateFormat(item.Mozart[i].Info.Suggestion.Zh, flatValues[j])
					if err != nil {
						return err
					}
					iSuggestionEn, err := mozartcommon.TemplateFormat(item.Mozart[i].Info.Suggestion.En, flatValues[j])
					if err != nil {
						return err
					}

					priority = item.Mozart[i].Info.Priority
					ruleType = item.Mozart[i].Info.RuleType
					ruleTypeZh = model.TranslateRuleType(ruleType)
					ruleTypeEn = model.TranslateENRuleType(ruleType)
					if item.Mozart[i].Info.Urgency {
						hThreats = 1
					}
					tags := Tags(item.Tags)
					// 增加mozart规则
					rule = generateRule(category, categoryZh, iRuleEnName.(string), ruleZhName.(string), iDescEn.(string), iDescZh.(string), priority, ruleTypeEn, ruleTypeZh, hid, hThreats, iSuggestionEn.(string), iSuggestionZh.(string), tags)
					rules[rule.Category] = append(rules[rule.Category], rule)
				}

			}
			continue
		}

		ruleType, err := model.GetInfoFromOutput("rule_type=", item.Output)
		if err != nil {
			ruleType = "Other"
		}
		ruleTypeZh = model.TranslateRuleType(ruleType)
		ruleTypeEn = model.TranslateENRuleType(ruleType)
		descriptionZh = ""
		zhMsg, err := model.GetInfoFromOutput("zh_msg=", item.Output)
		if err != nil {
			continue
		}

		if len(strings.Split(zhMsg, ";")) < 2 {
			descriptionZh = strings.Split(zhMsg, ";")[0]
		} else {
			descriptionZh = strings.Split(zhMsg, ";")[1]
		}

		category = item.Category
		categoryZh = item.CategoryZh
		ruleName = item.Rule
		descriptionEn = item.Desc
		priority = item.Priority
		hid = item.HID
		suggestionEnV := ""
		suggestionEn, ok := item.Suggestion["en"]
		if ok {
			suggestionEnV = suggestionEn.Value
		}
		suggestionZhV := ""
		suggestionZh, ok := item.Suggestion["zh"]
		if ok {
			suggestionZhV = suggestionZh.Value
		}
		hThreats = item.HThreats
		tags := Tags(item.Tags)

		rule = generateRule(category, categoryZh, ruleName, descriptionZh, descriptionEn, descriptionZh, priority, ruleTypeEn, ruleTypeZh, hid, hThreats, suggestionEnV, suggestionZhV, tags)
		rules[rule.Category] = append(rules[rule.Category], rule)
	}

	for category, cRules := range rules {
		err := cli.ResetCategoryRules(ctx, category, cRules, version)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("reset category %s rules error", category)
			return err
		}
	}
	return nil
}

func generateRule(category, categoryZh, name, ruleZhName, description, descriptionZh, priority, ruleTypeEn, ruleTypeZh, hid string, hthreats uint8, suggestion, suggestionZh string, tags Tags) *PalaceRule {
	var rule = &PalaceRule{
		Module:      module,
		Category:    category,
		Name:        name,
		Description: description,
		Severity:    int(model.Str2SeverityNum(priority)),
		CustomKV: CustomKV{
			{
				KVHash: KVHash{
					EN: KV{Key: "ruleType", Value: ruleTypeEn},
					ZH: KV{Key: "规则类型", Value: ruleTypeZh},
				},
			},
		},
		MultiLanguage: MultiLanguage{
			"name": {
				ValueHash: ValueHash{
					ZH: ruleZhName,
					EN: name,
				},
			},
			"description": {
				ValueHash: ValueHash{
					ZH: descriptionZh,
					EN: description,
				},
			},
			"module": {
				ValueHash: ValueHash{
					ZH: moduleZh,
					EN: module,
				},
			},
			"category": {
				ValueHash: ValueHash{
					ZH: categoryZh,
					EN: category,
				},
			},
		},
		Tags: tags,
	}

	if suggestion != "" && suggestionZh != "" {
		rule.CustomKV = append(rule.CustomKV, KVH{
			KVHash: KVHash{
				EN: KV{Key: "Suggestions", Value: suggestion},
				ZH: KV{Key: "处置建议", Value: suggestionZh},
			},
		})
	}

	rule.CustomKV = append(rule.CustomKV, KVH{
		KVHash: KVHash{
			EN: KV{Key: EnHthreatsKey, Value: getHthreatsValue(hthreats, lang.LanguageEN)},
			ZH: KV{Key: ZhHthreatsKey, Value: getHthreatsValue(hthreats, lang.LanguageZH)},
		},
	})

	return rule
}

const (
	EnHthreatsKey = "High-risk threat"
	ZhHthreatsKey = "是否需要紧急处理"
)

func getHthreatsValue(hthreats uint8, l lang.LanguageType) string {
	switch l {
	case lang.LanguageZH:
		if hthreats == 0 {
			return "否"
		}
		return "是"
	default:
		if hthreats == 0 {
			return "No"
		}
		return "Yes"
	}
}

package echelper

import (
	"context"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/pb"
)

const (
	internalAttributePrefix = "__internal__"
	timeout                 = time.Second * 5
	module                  = "ContainerSecurity"
	moduleZh                = "容器安全"
)

func SendRulesToEventCenter(ctx context.Context, cli *SherlockClient, rulesData []byte, version string) error {
	var fDataRules []model.RuleFromYaml
	err := yaml.Unmarshal(rulesData, &fDataRules)
	if err != nil {
		return err
	}

	var rules = make(map[string][]*pb.DetectionRule, 3)
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
		var hid string
		var hthreats uint8
		var suggestion map[string]*model.KV

		var rule *pb.DetectionRule

		if len(item.Mozart) != 0 {
			for i := range item.Mozart {
				category = "ATT&CK"
				categoryZh = "ATT&CK"
				for j := range item.Mozart[i].Steps {
					if item.Mozart[i].Steps[j].Name == "execGenerateSignal" {
						params, _ := item.Mozart[i].Steps[j].Params.(map[interface{}]interface{})
						for k, v := range params {
							if k.(string) == "rule" {
								ruleName = v.(string)
							}
						}
					}
				}
				descriptionEn = item.Mozart[i].Info.Desc.En
				descriptionZh = item.Mozart[i].Info.Desc.Zh
				priority = item.Mozart[i].Info.Priority
				ruleType = item.Mozart[i].Info.RuleType
				ruleTypeZh = model.TranslateRuleType(ruleType)
				if item.Mozart[i].Info.Urgency {
					hthreats = 1
				}
				suggestion = map[string]*model.KV{
					"en": {
						Key:   "Suggestions",
						Value: item.Mozart[i].Info.Suggestion.En,
					},
					"zh": {
						Key:   "处置建议",
						Value: item.Mozart[i].Info.Suggestion.Zh,
					},
				}
				// 增加mozart规则
				if ruleName == "" {
					continue
				}
				rule = generateRule(category, categoryZh, ruleName, descriptionEn, descriptionZh, priority, ruleType, ruleTypeZh, hid, hthreats, suggestion)
				rules[rule.Category] = append(rules[rule.Category], rule)
			}
			continue
		}

		ruleType, err := model.GetInfoFromOutput("rule_type=", item.Output)
		if err != nil {
			ruleType = "Other"
		}
		ruleTypeZh = model.TranslateRuleType(ruleType)
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
		suggestion = item.Suggestion
		hthreats = item.Hthreats

		rule = generateRule(category, categoryZh, ruleName, descriptionEn, descriptionZh, priority, ruleType, ruleTypeZh, hid, hthreats, suggestion)
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

func generateRule(category, categoryZh, name, description, descriptionZh, priority, ruleType, ruleTypeZh, hid string, hthreats uint8, suggestion map[string]*model.KV) *pb.DetectionRule {
	var rule = &pb.DetectionRule{
		Module:      module,
		Category:    category,
		Name:        name,
		Description: description,
		Severity:    uint32(model.Str2SeverityNum(priority)),
		CustomKV: []*pb.MultiLanguageKV{
			{
				KVHash: map[string]*pb.KV{
					string(lang.LanguageEN): {Key: "ruleType", Value: ruleType},
					string(lang.LanguageZH): {Key: "规则类型", Value: ruleTypeZh},
				},
			},
			//{
			//	KVHash: map[string]*pb.KV{
			//		string(lang.LanguageEN): {Key: internalAttributePrefix + "hid", Value: hid},
			//	},
			//},
		},
		MultiLanguage: map[string]*pb.MultiLanguageValue{
			"description": {
				ValueHash: map[string]string{
					string(lang.LanguageZH): descriptionZh,
				},
			},
			"module": {
				ValueHash: map[string]string{
					string(lang.LanguageZH): moduleZh,
				},
			},
			"category": {
				ValueHash: map[string]string{
					string(lang.LanguageZH): categoryZh,
				},
			},
		},
	}

	if len(suggestion) > 0 {
		var kvHash = make(map[string]*pb.KV, len(suggestion))
		for l, v := range suggestion {
			if l == "" || v == nil {
				continue
			}
			kvHash[l] = &pb.KV{
				Key:   v.Key,
				Value: v.Value,
			}
		}
		if len(kvHash) > 0 {
			rule.CustomKV = append(rule.CustomKV, &pb.MultiLanguageKV{
				KVHash: kvHash,
			})
		}
	}

	rule.CustomKV = append(rule.CustomKV, &pb.MultiLanguageKV{
		KVHash: map[string]*pb.KV{
			string(lang.LanguageEN): {Key: EnHthreatsKey, Value: getHthreatsValue(hthreats, lang.LanguageEN)},
			string(lang.LanguageZH): {Key: ZhHthreatsKey, Value: getHthreatsValue(hthreats, lang.LanguageZH)},
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

package holmeshelper

import (
	"context"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/pb"
	"gopkg.in/yaml.v2"
)

const (
	internalAttributePrefix = "__internal__"
)

func SendRulesToEventCenter(ctx context.Context, cli *echelper.EventCenterClient, rulesData []byte) error {
	const (
		timeout  = time.Second * 5
		module   = "ContainerSecurity"
		moduleZh = "容器安全"
	)
	var fDataRules []model.RuleFromYaml
	err := yaml.Unmarshal(rulesData, &fDataRules)
	if err != nil {
		return err
	}

	var rules = make(map[string][]*pb.DetectionRule, 3)
	for _, item := range fDataRules {
		if len(item.Rule) == 0 || len(item.Priority) == 0 {
			continue
		}
		if item.Category == "" {
			item.Category = "ATT&CK"
		}

		ruleType, err := model.GetInfoFromOutput("rule_type=", item.Output)
		if err != nil {
			ruleType = "Other"
		}
		ruleTypeZh := model.TranslateRuleType(ruleType)
		descZh := ""
		zhMsg, err := model.GetInfoFromOutput("zh_msg=", item.Output)
		if err != nil {
			continue
		}

		if len(strings.Split(zhMsg, ";")) < 2 {
			descZh = strings.Split(zhMsg, ";")[0]
		} else {
			descZh = strings.Split(zhMsg, ";")[1]
		}

		var rule = &pb.DetectionRule{
			Module:      module,
			Category:    item.Category,
			Name:        item.Rule,
			Description: item.Desc,
			Severity:    uint32(model.Str2SeverityNum(item.Priority)),
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						string(lang.LanguageEN): {Key: "ruleType", Value: ruleType},
						string(lang.LanguageZH): {Key: "规则类型", Value: ruleTypeZh},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						string(lang.LanguageEN): {Key: internalAttributePrefix + "hid", Value: item.HID},
					},
				},
			},
			MultiLanguage: map[string]*pb.MultiLanguageValue{
				"description": {
					ValueHash: map[string]string{
						string(lang.LanguageZH): descZh,
					},
				},
				"module": {
					ValueHash: map[string]string{
						string(lang.LanguageZH): moduleZh,
					},
				},
				"category": {
					ValueHash: map[string]string{
						string(lang.LanguageZH): item.CategoryZh,
					},
				},
			},
		}

		if len(item.Suggestion) > 0 {
			var kvHash = make(map[string]*pb.KV, len(item.Suggestion))
			for l, v := range item.Suggestion {
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
				string(lang.LanguageEN): {Key: EnHthreatsKey, Value: getHthreatsValue(item.Hthreats, lang.LanguageEN)},
				string(lang.LanguageZH): {Key: ZhHthreatsKey, Value: getHthreatsValue(item.Hthreats, lang.LanguageZH)},
			},
		})

		rules[rule.Category] = append(rules[rule.Category], rule)
	}

	for category, crules := range rules {
		err := cli.ResetCategoryRules(ctx, module, category, crules)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("reset category %s rules error", category)
			return err
		}
	}
	return nil
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

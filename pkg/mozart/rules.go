package mozart

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mozartcommon"
	"gitlab.com/security-rd/go-pkg/logging"
	gpModel "gitlab.com/security-rd/go-pkg/model"
)

// 规则开关的控制逻辑：
//   falco是否关闭，取决于一对多的mozart是否全部关闭
//
//   分支mozart是否关闭，取决于分支中的规则是否全部关闭
//   关联mozart是否关闭，取决于依赖它的mozart规则是否全部关闭
//   普通mozart是否关闭，取决于自身是否关闭
//
//   页面上规则是否关闭，取决于规则文件和开关配置是否有一个为关闭

func CheckFalcoDisabled(falcoRule model.FalcoYaml, mozartMap map[string]gpModel.MozartYaml, falcoMozartMap map[string][]string, mozartBranches map[string][]Rule, mozartUsersMap map[string][]Rule, reverseUserRelateds map[string][]Rule, userClosedRulesMap map[string]struct{}) (bool, error) {
	mozartNames, ok := falcoMozartMap[falcoRule.Rule]
	if !ok {
		return true, nil
	}

	for i := range mozartNames {
		if m, ok := mozartMap[mozartNames[i]]; ok {
			disabled, err := CheckMozartDisabled(m, mozartBranches, mozartUsersMap, userClosedRulesMap, reverseUserRelateds)
			if err != nil {
				logging.Get().Error().Err(err).Msg("CheckMozartDisabled fails")
				return true, err
			}
			if !disabled {
				return false, nil
			}
		}
	}

	return true, nil
}

func CheckMozartDisabled(checkRule gpModel.MozartYaml, mozartBranches, mozartUsersMap map[string][]Rule, userClosedRulesMap map[string]struct{}, reverseUserRelateds map[string][]Rule) (bool, error) {
	// 检查branches下的 user rule 是否都是关闭
	if branches, ok := mozartBranches[checkRule.Key]; ok {
		for i := range branches {
			if _, ok := userClosedRulesMap[branches[i].Name]; !ok && branches[i].Enabled {
				return false, nil
			}
		}
		return true, nil
	}

	// 检查依赖此规则的其他 user rule 是否都是关闭
	if mozartcommon.IsMozartRelatedRule(checkRule) {
		if ms, ok := reverseUserRelateds[checkRule.Key]; ok {
			for i := range ms {
				if _, ok := userClosedRulesMap[ms[i].Name]; !ok && ms[i].Enabled {
					return false, nil
				}
			}
		}
	}

	userEnabled := false
	for i := range mozartUsersMap[checkRule.Key] {
		if _, ok := userClosedRulesMap[mozartUsersMap[checkRule.Key][i].Name]; !ok {
			userEnabled = true
			break
		}
	}
	//if userEnabled && !checkRule.Disabled {
	if userEnabled { // userClosedRules 已经在console侧包含了 规则文件 和 用户开关 的取并逻辑
		return false, nil
	}

	return true, nil
}

// 构建mozart -> branch的关系
func BuildMozartBranches(userRules []Rule) map[string][]Rule {
	userBranches := make(map[string][]Rule)
	for i := range userRules {
		if userRules[i].Key != userRules[i].Name { // 说明这个规则是通过branch派生出来的
			if rs, ok := userBranches[userRules[i].Key]; ok {
				userBranches[userRules[i].Key] = append(rs, userRules[i])
			} else {
				userBranches[userRules[i].Key] = []Rule{userRules[i]}
			}
		}
	}
	return userBranches
}

// 构建已关闭的用户规则map
func BuildUserClosedRulesMap(rules []string) map[string]struct{} {
	rulesMap := make(map[string]struct{}, len(rules))
	for i := range rules {
		rulesMap[rules[i]] = struct{}{}
	}
	return rulesMap
}

// 构建反向的 user rule 和related关系，related -> user rules
func BuildReverseUserRelateds(userRules []Rule) map[string][]Rule {
	reverseMozartRelated := make(map[string][]Rule)
	for i := range userRules {
		if userRules[i].Relateds != nil {
			for j := range userRules[i].Relateds {
				if mozarts, ok := reverseMozartRelated[userRules[i].Relateds[j].RuleName]; ok {
					reverseMozartRelated[userRules[i].Relateds[j].RuleName] = append(mozarts, userRules[i])
				} else {
					reverseMozartRelated[userRules[i].Relateds[j].RuleName] = []Rule{userRules[i]}
				}
			}
		}
	}
	return reverseMozartRelated
}

func userRuleType(tags []string) string {
	for i := range tags {
		if tags[i] == "related" {
			return "mozart_related"
		}
	}
	return "mozart"
}

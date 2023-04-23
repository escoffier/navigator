package attck

import (
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	DefaultEliminatedTag = "4t"
)

func ReadFromConfig(origin string) map[string]struct{} {
	tags := strings.Split(origin, ",")
	tagsMap := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tagsMap[strings.TrimSpace(tag)] = struct{}{}
	}
	return tagsMap
}

func IsRule4PocIgnored(rule model.RuleFromYaml, displayedTags map[string]struct{}) bool {
	// 规则tag配置4t，为跳过的前提
	is4Poc := false
	for _, tag := range rule.Tags {
		if tag == DefaultEliminatedTag {
			is4Poc = true
			break
		}
	}
	// 规则的tag 没有配置4t，不跳过
	if !is4Poc {
		return false
	}
	// 规则的tag配置了4t ↓

	// 没有DP的tag，跳过
	if len(displayedTags) == 0 {
		return true
	}

	// 规则的tag在DP的tag中，表示这个规则要展示，不能跳过
	for _, tag := range rule.Tags {
		if _, ok := displayedTags[tag]; ok {
			return false
		}
	}
	return true
}

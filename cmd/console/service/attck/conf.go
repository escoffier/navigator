package attck

import (
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	DefaultElimatedTag = "4t"
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
	is4Poc := false
	for _, tag := range rule.Tags {
		if tag == DefaultElimatedTag {
			is4Poc = true
			break
		}
	}
	if !is4Poc {
		return false
	}
	if len(displayedTags) == 0 {
		return true
	}

	for _, tag := range rule.Tags {
		if _, ok := displayedTags[tag]; ok {
			return false
		}
	}
	return true
}

package holmesengine

import (
	"strings"
)

const (
	macroNameTensorsecnamespace = "tensorsec_namespace"
)

func boolPtr(b bool) *bool { return &b }

func GetRuleSwitchMutationFunc(closedRules map[string]struct{}, initPhase bool) MutationFunc {
	return func(elementLines []string) (newLines []string, err error) {
		newLines = make([]string, 0, len(elementLines))
		// Because of the latency of load use configs from the storage, there might be some alerts with the disabled rules when the engine starts; defaultly disable them in init phase.
		isStrictInInitPhase := false
		if len(closedRules) == 0 && initPhase {
			for _, line := range elementLines {
				if pos := strings.Index(line, "tags:"); pos == 2 {
					if strings.Index(line, "strict") > 0 {
						isStrictInInitPhase = true
					}
				}
			}
		}

		for _, line := range elementLines {
			newLines = append(newLines, line)
			if pos := strings.Index(line, "rule:"); pos == 2 {
				ruleName := strings.TrimSpace(line[pos+5:])
				if _, exist := closedRules[ruleName]; exist {
					newLines = append(newLines, "  enabled: false")
				} else if isStrictInInitPhase {
					newLines = append(newLines, "  enabled: false")
				}
			}
		}
		return newLines, nil
	}
}

func GetTensorsecNamespaceChange(myNamespace string) MutationFunc {
	return func(elementLines []string) ([]string, error) {
		isTarget := false
		for _, line := range elementLines {
			if pos := strings.Index(line, "macro:"); pos == 2 {
				if strings.TrimSpace(line[pos+6:]) == macroNameTensorsecnamespace {
					isTarget = true
					break
				}
			}
		}
		if !isTarget {
			return elementLines, nil
		}
		newLines := make([]string, 0, len(elementLines))
		for _, line := range elementLines {
			if pos := strings.Index(line, "condition:"); pos == 2 {
				line = strings.ReplaceAll(line, "tensorsec", myNamespace)
			}
			newLines = append(newLines, line)
		}
		return newLines, nil
	}
}

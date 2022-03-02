package holmesengine

import (
	"errors"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"
)

type MutationFunc func(elementLines []string) (newLines []string, err error)

func rulesCheck(new, prev []string) error {
	targetNameNew, targetNamePrev := "", ""
	for _, l := range new {
		if pos := strings.Index(l, "rule:"); pos == 2 {
			targetNameNew = strings.TrimSpace(l[pos+5:])
		} else if pos := strings.Index(l, "list:"); pos == 2 {
			targetNameNew = strings.TrimSpace(l[pos+5:])
		} else if pos := strings.Index(l, "macro:"); pos == 2 {
			targetNameNew = strings.TrimSpace(l[pos+6:])
		} else if pos := strings.Index(l, "required_engine_version:"); pos == 2 {
			targetNameNew = strings.TrimSpace(l[pos+len("required_engine_version:"):])
		}
	}
	if targetNameNew == "" {
		return errors.New("missing names")
	}
	for _, l := range prev {
		if pos := strings.Index(l, "rule:"); pos == 2 {
			targetNamePrev = strings.TrimSpace(l[pos+5:])
		} else if pos := strings.Index(l, "list:"); pos == 2 {
			targetNamePrev = strings.TrimSpace(l[pos+5:])
		} else if pos := strings.Index(l, "macro:"); pos == 2 {
			targetNamePrev = strings.TrimSpace(l[pos+6:])
		} else if pos := strings.Index(l, "required_engine_version:"); pos == 2 {
			targetNamePrev = strings.TrimSpace(l[pos+len("required_engine_version:"):])
		}
	}
	if targetNameNew != targetNamePrev {
		return errors.New("cannot mutate name")
	}
	return nil
}

func RulesMutate(ruleBytes []byte, mutationFuncs ...MutationFunc) ([]byte, error) {
	ruleStr := string(ruleBytes)
	lines := strings.Split(ruleStr, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		isComment := false
		for _, c := range line {
			if c == ' ' {
				continue
			}
			if c == '#' {
				isComment = true
				break
			}
			break
		}
		if isComment {
			continue
		}
		filtered = append(filtered, line)
	}

	buffer := make([]string, 0, 10)
	newRulesLines := make([]string, 0, len(filtered)*2)
	for _, line := range filtered {
		if strings.Index(line, "- ") == 0 {
			if len(buffer) > 0 {
				prev := buffer
				for _, mfunc := range mutationFuncs {
					newLines, err := mfunc(buffer)
					if err != nil {
						logging.Get().Err(err).Msgf("mutate err. lines: %v", buffer)
					} else {
						buffer = newLines
					}
				}
				if err := rulesCheck(buffer, prev); err != nil {
					logging.Get().Err(err).Msgf("mutate err. lines: %v", buffer)
					newRulesLines = append(newRulesLines, prev...)
				} else {
					newRulesLines = append(newRulesLines, buffer...)
				}
				buffer = make([]string, 0, len(buffer))

			}
		}
		buffer = append(buffer, line)
	}
	if len(buffer) > 0 {
		prev := buffer
		for _, mfunc := range mutationFuncs {
			newLines, err := mfunc(buffer)
			if err != nil {
				logging.Get().Err(err).Msgf("mutate err. lines: %v", buffer)
			} else {
				buffer = newLines
			}
		}
		if err := rulesCheck(buffer, prev); err != nil {
			logging.Get().Err(err).Msgf("mutate err. lines: %v", buffer)
			newRulesLines = append(newRulesLines, prev...)
		} else {
			newRulesLines = append(newRulesLines, buffer...)
		}
	}

	newRuleStr := strings.Join(newRulesLines, "\n")
	return []byte(newRuleStr), nil
}

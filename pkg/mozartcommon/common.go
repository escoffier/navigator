// Package mozartcommon
// 暂时先放在这里，因为共用的方法需要给console调用，但mozart包中尚且存留了一些外部依赖，会导致console编译失败等问题。
package mozartcommon

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	marcoPrefix = "MARCO::"
)

func ExtractValues(ctx context.Context, configStep model.ConfigMozartStep, mozartMarco []model.ConfigMozartMarco, key string) (map[string]interface{}, error) {
	values := map[string]interface{}{}
	switch configStep.Name {
	case "defineValue":
		p := configStep.Params.(map[interface{}]interface{})
		for k, v := range p {
			sk := k.(string)
			if CheckKey(sk) {
				continue
			}
			values[sk] = v
		}
	case "branches":
		branchesName := strings.TrimPrefix(configStep.Params.(string), marcoPrefix)
		for i := range mozartMarco {
			if mozartMarco[i].Key != branchesName {
				continue
			}
			for j := range mozartMarco[i].Branches {
				branchKey := key + "-" + strconv.Itoa(j)
				if !mozartMarco[i].Branches[j].Enabled && !mozartMarco[i].Branches[j].Default {
					continue
				}
				for k := range mozartMarco[i].Branches[j].Steps {
					branchStepValues, err := ExtractValues(ctx, mozartMarco[i].Branches[j].Steps[k], mozartMarco, branchKey)
					if err != nil {
						continue
					}
					for ik, iv := range branchStepValues {
						if m, ok := values[branchKey].(map[string]interface{}); !ok {
							values[branchKey] = map[string]interface{}{ik: iv}
						} else {
							m[ik] = iv
							values[branchKey] = m
						}
					}
				}
			}
		}
	}
	return values, nil
}

func TemplateFormat(format interface{}, values map[string]interface{}) (interface{}, error) {
	switch format.(type) {
	case string:
		return templateFormatString(format.(string), values)
	case []string:
		formats := format.([]string)
		for i := range formats {
			result, err := templateFormatString(formats[i], values)
			if err != nil {
				return format, err
			}
			formats[i] = result
		}
		return formats, nil
	case []interface{}:
		formats := format.([]interface{})
		for i := range formats {
			result, err := TemplateFormat(formats[i], values)
			if err != nil {
				return format, err
			}
			formats[i] = result
		}
		return formats, nil
	case map[string]interface{}:
		formats := format.(map[string]interface{})
		for k, v := range formats {
			result, err := TemplateFormat(v, values)
			if err != nil {
				return format, err
			}
			formats[k] = result
		}
		return formats, nil
	default:
		return format, nil
	}
}

func templateFormatString(format string, values map[string]interface{}) (string, error) {
	re := regexp.MustCompile(`{[^{"]*?:[^{"]*?}`)
	results := re.FindAllString(format, -1)
	defaultMap := make(map[string]interface{})
	for i := range results {
		key := strings.TrimSpace(strings.Split(strings.Split(results[i], "{")[1], ":")[0])
		value := strings.TrimSpace(strings.Split(strings.Split(strings.Split(results[i], "{")[1], ":")[1], "}")[0])
		defaultMap[key] = value
		format = strings.Replace(format, results[i], "{"+key+"}", 1)
	}
	args, i := make([]string, len(values)*2), 0
	for k, v := range values {
		args[i] = "{" + k + "}"
		args[i+1] = fmt.Sprint(v)
		i += 2
	}
	afterFormat := strings.NewReplacer(args...).Replace(format)
	defaultRe := regexp.MustCompile(`{[^{]*?}`)
	afterResults := defaultRe.FindAllString(afterFormat, -1)
	if len(afterResults) != 0 {
		ar2 := make([]string, 0)
		for i := range afterResults {
			if strings.Contains(afterResults[i], "\"") {
				continue
			}
			ar2 = append(ar2, afterResults[i])
		}
		for i := range ar2 {
			k := ar2[i][1 : len(ar2[i])-1]
			if _, ok := defaultMap[k]; !ok {
				err := errors.New("some key has no value")
				logging.Get().Error().Err(err).Interface("key", k).Interface("default values", defaultMap).Msg("some key has no value")
				return afterFormat, err
			}
		}
		if len(ar2) != 0 && len(defaultMap) != 0 {
			return templateFormatString(afterFormat, defaultMap)
		} else {
			return afterFormat, nil
		}
	} else {
		return afterFormat, nil
	}
}

func FlatValues(values map[string]interface{}) []map[string]interface{} {
	flag := false
	moreValues := make([]map[string]interface{}, 0)
	for k, v := range values {
		if CheckKey(k) {
			flag = true
			if mv, ok := v.(map[string]interface{}); ok {
				vs := FlatValues(mv)
				for i := range vs {
					tempValues := map[string]interface{}{}
					for ik, iv := range vs[i] {
						tempValues[ik] = iv
					}
					for jk, jv := range values {
						if _, ok := tempValues[jk]; !ok {
							tempValues[jk] = jv
						}
					}
					moreValues = append(moreValues, tempValues)
				}
			}
		}
	}

	var result []map[string]interface{}
	if !flag {
		result = []map[string]interface{}{values}
	} else {
		for i := range moreValues {
			for jk, _ := range moreValues[i] {
				if CheckKey(jk) {
					delete(moreValues[i], jk)
				}
			}
		}
		result = moreValues
	}
	return result
}

func CheckKey(key string) bool {
	invalidElems := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-"}
	for i := range invalidElems {
		key = strings.ReplaceAll(key, invalidElems[i], "")
	}
	return len(key) == 0
}

// Package mozartcommon
// 暂时先放在这里，因为共用的方法需要给console调用，但mozart包中尚且存留了一些外部依赖，会导致console编译失败等问题。
package mozartcommon

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	gpModel "gitlab.com/security-rd/go-pkg/model"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	marcoPrefix = "MARCO::"

	marcoTypeBranchSerial   = "branches_serial"
	marcoTypeBranchParallel = "branches_parallel"
)

var (
	marcoTypes = []string{marcoTypeBranchSerial, marcoTypeBranchParallel}
)

func ExtractValues(ctx context.Context, configStep model.ConfigMozartStep, mozartMarco []model.MozartYaml, key string) (map[string]interface{}, map[string]interface{}, error) {
	values := map[string]interface{}{}
	switches := map[string]interface{}{}
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
				//if !mozartMarco[i].Branches[j].Enabled && !mozartMarco[i].Branches[j].Default {
				//	continue
				//}
				for k := range mozartMarco[i].Branches[j].Steps {
					branchStepValues, branchStepSwitches, err := ExtractValues(ctx, mozartMarco[i].Branches[j].Steps[k], mozartMarco, branchKey)
					if err != nil {
						continue
					}
					if len(branchStepValues) == 0 {
						values[branchKey] = map[string]interface{}{}
					} else {
						for ik, iv := range branchStepValues {
							if m, ok := values[branchKey].(map[string]interface{}); !ok {
								values[branchKey] = map[string]interface{}{ik: iv}
							} else {
								m[ik] = iv
								values[branchKey] = m
							}
						}
					}
					if len(branchStepSwitches) == 0 {
						switches[branchKey] = map[string]interface{}{"enabled": !mozartMarco[i].Branches[j].Disabled}
					} else {
						for ik, iv := range branchStepSwitches {
							if m, ok := switches[branchKey].(map[string]interface{}); !ok {
								switches[branchKey] = map[string]interface{}{ik: iv}
							} else {
								m[ik] = iv
								switches[branchKey] = m
							}
						}
					}
				}
			}
		}
	}
	return values, switches, nil
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
	var err error
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
	if len(defaultMap) == 0 && len(afterResults) != 0 {
		return afterFormat, errors.New("some key has no value")
	}
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
				// 使用默认值仍然无法format全部变量，记录error。并将剩下的变量format完成。
				err = errors.New("some key has no value")
				logging.Get().Error().Err(err).Interface("key", k).Interface("default values", defaultMap).Msg("some key has no value")
				//return afterFormat, err
			}
		}
		if len(ar2) != 0 && len(defaultMap) != 0 {
			afterFormat, _ = templateFormatString(afterFormat, defaultMap)
			return afterFormat, err
		} else {
			return afterFormat, err
		}
	} else {
		return afterFormat, nil
	}
}

func Flatten(m map[string]interface{}) []map[string]interface{} {
	var res []map[string]interface{}
	rm := make(map[string]interface{})
	for k, v := range m {
		if reflect.TypeOf(v).Kind() == reflect.Map {
			for _, val := range Flatten(v.(map[string]interface{})) {
				res = append(res, val)
			}
		} else {
			rm[k] = v
		}
	}
	if len(rm) != 0 {
		res = append(res, rm)
	}

	resultMap := make(map[string]struct{})
	newResult := make([]map[string]interface{}, 0)
	for i := range res {
		br, _ := json.Marshal(res[i])
		m := md5.New()
		m.Write(br)
		hash := hex.EncodeToString(m.Sum(nil))
		if _, ok := resultMap[hash]; ok {
			continue
		}
		resultMap[hash] = struct{}{}
		newResult = append(newResult, res[i])
	}

	return newResult
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

	resultMap := make(map[string]struct{})
	newResult := make([]map[string]interface{}, 0)
	for i := range result {
		br, _ := json.Marshal(result[i])
		m := md5.New()
		m.Write(br)
		hash := hex.EncodeToString(m.Sum(nil))
		if _, ok := resultMap[hash]; ok {
			continue
		}
		resultMap[hash] = struct{}{}
		newResult = append(newResult, result[i])
	}

	return newResult
}

func CheckKey(key string) bool {
	invalidElems := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-"}
	for i := range invalidElems {
		key = strings.ReplaceAll(key, invalidElems[i], "")
	}
	return len(key) == 0
}

func CheckDefaultFormatValue(s string) bool {
	re := regexp.MustCompile(`{[^{"]*?:[^{"]*?}`)
	results := re.FindAllString(s, -1)
	return len(results) != 0
}

func IsMozartMarco(my model.MozartYaml) bool {
	return util.ContainsString(marcoTypes, my.Type)
}

func IsMozartMarco2(my gpModel.MozartYaml) bool {
	return util.ContainsString(marcoTypes, my.Type)
}

func IsMarco(my model.MozartYaml) bool {
	return my.Macro != "" || my.List != ""
}

func IsMarco2(my gpModel.MozartYaml) bool {
	return my.Macro != "" || my.List != ""
}

func IsMozartRule(my model.MozartYaml) bool {
	// todo: 这里要不要加 ！related
	return !IsMozartMarco(my) && !IsMarco(my) && !util.ContainsString(my.Info.Tags, "related")
}

func IsMozartRelatedRule(my gpModel.MozartYaml) bool {
	return !IsMozartMarco2(my) && !IsMarco2(my) && util.ContainsString(my.Info.Tags, "related")
}

func VersionSeg1(vs string) int {
	re := regexp.MustCompile(`^v(\d+)(\.)(\d+)$`)
	match := re.FindStringSubmatch(vs)
	if len(match) != 4 {
		return 1
	}
	seg1, err := strconv.Atoi(match[1])
	if err != nil {
		return 1
	}
	return seg1
}

func CategoryFromTags(tags []string) (string, string) {
	for i := range tags {
		if tags[i] == model.RuleCategoryATTCK {
			return model.RuleCategoryATTCK, model.RuleCategoryZHATTCK
		}
		if tags[i] == model.RuleCategoryWatson {
			return model.RuleCategoryWatson, model.RuleCategoryZHWatson
		}
	}
	return "", ""
}

func MozartMarcoV2ToV3(olds []model.ConfigMozartMarco) []model.MozartYaml {
	news := make([]model.MozartYaml, len(olds))
	for i := range olds {
		news[i] = model.MozartYaml{Key: olds[i].Key, Type: olds[i].Type, Branches: olds[i].Branches}
	}
	return news
}

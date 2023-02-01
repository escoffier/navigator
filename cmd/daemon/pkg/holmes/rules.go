package holmes

import (
	"bytes"
	"context"

	"github.com/spf13/viper"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 1. 基础规则（触发+关联）如果含有strict tag，直接标记为disable
// 2. 如果某个关联规则没有任何mozart enable，则它应该是disable
func extractDisabledRulesFromRules(ctx context.Context, ruleBytes []byte) (map[string]struct{}, error) {
	config := model.OriginConfigs{}
	disabledM := make(map[string]struct{})
	enabledM := make(map[string]struct{})
	v := viper.New()
	v.SetConfigType("yaml")
	prefix := []byte("config:\n") // 加这个前缀的目的是因为：viper不能读取纯list的yaml，可能是我不会

	err := v.ReadConfig(bytes.NewBuffer(append(prefix, ruleBytes...)))
	if err != nil {
		return disabledM, err
	}
	if err := v.Unmarshal(&config); err != nil {
		return disabledM, err
	}

	data := config.Config
	for i := range data {
		// 非mozart
		if len(data[i].Mozart) == 0 {
			if util.ContainsString(data[i].Tags, "strict") {
				disabledM[data[i].Rule] = struct{}{}
			}
			continue
		}
		// mozart
		for j := range data[i].Mozart {
			if data[i].Mozart[j].Enabled {
				for k := range data[i].Mozart[j].Steps {
					if data[i].Mozart[j].Steps[k].Name != "checkRelatedExists" {
						continue
					}
					if params, ok := data[i].Mozart[j].Steps[k].Params.([]string); ok {
						enabledM[params[0]] = struct{}{}
					}
				}
			}

			if !data[i].Mozart[j].Enabled {
				for k := range data[i].Mozart[j].Steps {
					if data[i].Mozart[j].Steps[k].Name != "checkRelatedExists" {
						continue
					}
					if params, ok := data[i].Mozart[j].Steps[k].Params.([]string); ok {
						if _, ok := enabledM[params[0]]; !ok {
							disabledM[params[0]] = struct{}{}
						}
					}
				}
			}
		}
	}
	return disabledM, nil
}

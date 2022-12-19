package scan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	executorScanEnvName = "scan-env"
)

type ExecutorScanEnv struct {
	policy interface{}
}

func (e *ExecutorScanEnv) parseConfigEnv(env []string) []model.EnvKeyValue {
	var res []model.EnvKeyValue
	for _, v := range env {
		index := strings.Index(v, "=")
		if index == -1 {
			continue
		}
		tmpEnv := model.EnvKeyValue{}
		tmpEnv.Key = v[0:index]
		envLen := len(v)
		if index+1 < envLen {
			tmpEnv.Value = v[index+1:]
		}
		res = append(res, tmpEnv)
	}
	return res
}

func (e *ExecutorScanEnv) stringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

func ParseEnv(envs []string) []model.EnvKeyValue {
	res := make([]model.EnvKeyValue, 0)
	for i := range envs {
		split := strings.Split(envs[i], "=")
		if len(split) >= 2 {
			res = append(res, model.EnvKeyValue{
				Key:        strings.Trim(split[0], " "),
				Value:      strings.Trim(strings.Join(split[1:], "="), ""),
				IsAbnormal: 0,
			})
		}
	}
	return res
}

func (e *ExecutorScanEnv) Scan(ctx context.Context, param Param) (Artifact, error) {
	configJSON, ok := param["configJson"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'configJson' in parameter")
		return nil, errors.New("miss 'configJson' in parameter")
	}

	config := model.ConfigFile{}
	err := json.Unmarshal(e.stringToBytes(configJSON), &config)
	if err != nil {
		logging.GetLogger().Err(err).Msg("ScanEnv can't unmarshal configJson")
		return nil, errors.New("ScanEnv can't unmarshal configJson")
	}
	allEnvs := ParseEnv(config.Config.Env)
	r := make(map[string]interface{})
	var abnormalEnv []string

	policyRule, ok := e.policy.(task.EnvPolicy)
	if ok && len(policyRule.EnvName) > 0 {
		if err := json.Unmarshal([]byte(policyRule.EnvName), &abnormalEnv); err == nil {
			for i := range allEnvs {
				for j := range abnormalEnv {
					if allEnvs[i].Key == abnormalEnv[j] {
						allEnvs[i].IsAbnormal = consts.EnvIsAbnormal
						break
					}
				}
			}
		}
	}
	logging.GetLogger().Info().Msgf("after RESENV :%v", allEnvs)
	r["result"] = allEnvs
	return r, nil
}

func init() {
	err := Register(executorScanEnvName, newScanEnv)
	if err != nil {
		logging.GetLogger().Err(err).Str("executorName", executorScanEnvName).Msg("int executor err")
	}
}

func newScanEnv(config ExecutorConfig) (Executor, error) { // Open时调用
	e := &ExecutorScanEnv{}
	e.policy = config.Policy
	return e, nil
}

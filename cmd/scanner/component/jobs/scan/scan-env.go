package scan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
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

func (e *ExecutorScanEnv) Scan(ctx context.Context, param Param) (Artifact, error) {
	configJson, ok := param["configJson"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'configJson' in parameter")
		return nil, errors.New("miss 'configJson' in parameter")
	}

	config := model.ConfigFile{}
	err := json.Unmarshal(e.stringToBytes(configJson), &config)
	if err != nil {
		logging.GetLogger().Error().Msg("ScanEnv can't unmarshal configJson")
		return nil, errors.New("ScanEnv can't unmarshal configJson")
	}

	r := make(map[string]interface{})
	r["customFlag"] = 0
	policyRule, ok := e.policy.(task.EnvPolicy)
	var envs []string
	if !ok {
		logging.GetLogger().Error().Msg("miss 'EnvPolicyRule' in parameter")
		return nil, errors.New("miss 'EnvPolicyRule' in parameter")
	}
	if len(policyRule.EnvName) != 0 {
		err := json.Unmarshal([]byte(policyRule.EnvName), &envs)
		if err != nil {
			logging.GetLogger().Error().Msg("EnvPolicyRule can't unmarshal configJson")
			return nil, errors.New("EnvPolicyRule can't unmarshal configJson")
		}
	}

	resEnv := e.parseConfigEnv(config.Config.Env)
	if len(envs) > 0 {
		for _, v := range resEnv {
			for _, key := range envs { //数量较少，先暴力遍历
				if key == v.Key {
					v.IsAbnormal = 1
					r["customFlag"] = 1
				}
			}
		}
	}
	r["result"] = resEnv

	return r, nil
}

func init() {
	err := Register(executorScanEnvName, newScanEnv)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("executorName", executorScanEnvName).Msg("int executor err")
	}
}

func newScanEnv(config ExecutorConfig) (Executor, error) { //Open时调用
	e := &ExecutorScanEnv{}
	e.policy = config.Policy
	return e, nil
}

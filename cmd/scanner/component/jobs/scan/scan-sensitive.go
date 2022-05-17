package scan

import (
	"context"
	"errors"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	executorScanSensitiveName = "scan-sensitive"
)

type ExecutorScanSensitive struct {
	sensitiveScan component.SensitiveScan
	policy        interface{}
}

func (e *ExecutorScanSensitive) Scan(ctx context.Context, param Param) (Artifact, error) {
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		return nil, nil
	}
	layers, ok := param["layers"].([]string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'layersFilePath' in parameter")
		return nil, errors.New("miss 'layersFilePath' in parameter")
	}

	layersFilePath, ok := param["layersFilePath"].([]string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'layersFilePath' in parameter")
		return nil, errors.New("miss 'layersFilePath' in parameter")
	}

	r := make(map[string]interface{})
	r["customFlag"] = 0
	policyRule, ok := e.policy.(task.SensitiveFilePolicy)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'task.SensitiveFilePolicy' in parameter")
		return nil, errors.New("miss 'task.SensitiveFilePolicy' in parameter")
	}

	if len(policyRule.CustomFileName) == 0 {
		err := e.sensitiveScan.InitConfigFiles(filepath.Join("/configs", "scanner", "patterns.json")) // 改成从数据库中获取
		if err != nil {
			logging.GetLogger().Err(err).Msgf("init Sensitive regex failed")
			return nil, nil
		}
	} else {
		err := e.sensitiveScan.InitCustomConfig(policyRule.CustomFileName)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("init Sensitive regex failed")
			return nil, nil
		}
		r["customFlag"] = 1
	}
	resultSensitive := []model.PerLayerSensitiveResult{}
	for i := 1; i < len(layersFilePath); i++ {
		tmpLayerResult := model.PerLayerSensitiveResult{}
		tmpLayerResult.LayerDigest = layers[i]
		sensitives, err := e.sensitiveScan.FindSensitiveFileNamesInImage(filepath.Join(layersFilePath[i], "layer.tar"), e.sensitiveScan.SensitiveFilenameRegExp)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("scan %v err :", filepath.Join(layersFilePath[i], "layer.tar"))
			continue
		}
		tmpLayerResult.Sensitives = append(tmpLayerResult.Sensitives, sensitives...)
		resultSensitive = append(resultSensitive, tmpLayerResult)
	}

	r["result"] = resultSensitive
	return r, nil
}

func init() {
	err := Register(executorScanSensitiveName, newScanSensitive)
	if err != nil {
		logging.GetLogger().Err(err).Str("executorName", executorScanSensitiveName).Msg("init executor err")
	}
}

func newScanSensitive(config ExecutorConfig) (Executor, error) { // Open时调用
	e := &ExecutorScanSensitive{}
	e.sensitiveScan = component.SensitiveScan{}
	e.policy = config.Policy
	return e, nil
}

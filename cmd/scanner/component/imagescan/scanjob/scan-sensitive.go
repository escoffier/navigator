package scanjob

import (
	"context"
	"errors"
	"path/filepath"

	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ExecutorScanSensitive struct {
	sensitiveScan  component.SensitiveScan
	sensitiveRules []string
	mqWriter       mq.Writer
}

func (e *ExecutorScanSensitive) Scan(ctx context.Context, param Param) ([]model.PerLayerSensitiveResult, error) {
	resultSensitive := []model.PerLayerSensitiveResult{}
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		return resultSensitive, nil
	}
	layers, ok := param["layers"].([]string)
	if !ok {
		logging.Get().Error().Msg("miss 'layersFilePath' in parameter")
		return resultSensitive, errors.New("miss 'layersFilePath' in parameter")
	}

	layersFilePath, ok := param["layersFilePath"].([]string)
	if !ok {
		logging.Get().Error().Msg("miss 'layersFilePath' in parameter")
		return resultSensitive, errors.New("miss 'layersFilePath' in parameter")
	}

	// default policy
	err := e.sensitiveScan.InitConfigFiles(filepath.Join("/configs", "scanner", "patterns.json"))
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msgf("init Sensitive regex failed")
		return resultSensitive, err
	}
	// 自定义的规则
	_ = e.sensitiveScan.AddCustomConfig(e.sensitiveRules)

	for i := 1; i < len(layersFilePath); i++ {
		tmpLayerResult := model.PerLayerSensitiveResult{}
		tmpLayerResult.LayerDigest = layers[i]
		sensitives, err := e.sensitiveScan.FindSensitiveFileNamesInImage(filepath.Join(layersFilePath[i], "layer.tar"))
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msgf("scan %v err :", filepath.Join(layersFilePath[i], "layer.tar"))
			continue
		}
		tmpLayerResult.Sensitives = append(tmpLayerResult.Sensitives, sensitives...)
		resultSensitive = append(resultSensitive, tmpLayerResult)
	}

	return resultSensitive, nil
}

func NewScanSensitive(sensitiveRules []string, mqWriter mq.Writer) *ExecutorScanSensitive {
	e := &ExecutorScanSensitive{
		sensitiveScan:  component.SensitiveScan{MqWriter: mqWriter},
		sensitiveRules: sensitiveRules,
	}
	return e
}

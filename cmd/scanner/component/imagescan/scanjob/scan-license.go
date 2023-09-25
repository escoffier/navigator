package scanjob

import (
	"context"
	"errors"
	"path/filepath"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ExecutorScanLicense struct {
	LicenseScan component.LicenseScan
}

func (e *ExecutorScanLicense) Scan(ctx context.Context, param Param) ([]model.PerLayerLicenseResult, error) {
	e.LicenseScan.Init()
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		return nil, nil
	}
	layers, ok := param["layers"].([]string)
	if !ok {
		logging.Get().Error().Msg("miss 'layersFilePath' in parameter")
		return nil, errors.New("miss 'layersFilePath' in parameter")
	}

	layersFilePath, ok := param["layersFilePath"].([]string)
	if !ok {
		logging.Get().Error().Msg("miss 'layersFilePath' in parameter")
		return nil, errors.New("miss 'layersFilePath' in parameter")
	}

	result := make([]model.PerLayerLicenseResult, 0)
	for i := 1; i < len(layersFilePath); i++ {
		tmpRes, err := e.LicenseScan.ScanLayer(ctx, filepath.Join(layersFilePath[i], "layer.tar"))
		if err != nil {
			logging.Get().Warn().Msgf("License Scan %v Error err:%v", layersFilePath[i], err)
			return nil, err
		}
		tmpLayerResult := model.PerLayerLicenseResult{}
		tmpLayerResult.LayerDigest = layers[i]
		for k := range tmpRes {
			tmpLayerResult.LicenseInfos = append(tmpLayerResult.LicenseInfos, tmpRes[k])
		}
		result = append(result, tmpLayerResult)
	}
	return result, nil
}

func NewScanLicense(mqWriter mq.Writer) *ExecutorScanLicense {
	e := &ExecutorScanLicense{}
	e.LicenseScan = component.LicenseScan{MqWriter: mqWriter}
	return e
}

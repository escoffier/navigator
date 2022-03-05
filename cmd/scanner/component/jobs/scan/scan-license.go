package scan

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	executorScanLicenselName = "scan-license"
)

type executorScanLicense struct {
	// layerList     []string
	LicenseScan component.LicenseScan
	policy      interface{}
}

func (e *executorScanLicense) Scan(ctx context.Context, param Param) (Artifact, error) {
	e.LicenseScan.Init()
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

	policyRule, ok := e.policy.(task.LicensePolicy)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'policyRule' in Config will not scan license")
		return nil, errors.New("miss 'policyRule' in Config will not scan license")
	}
	var customLicenseList []string
	if len(policyRule.LicenseName) != 0 {
		err := json.Unmarshal([]byte(policyRule.LicenseName), &customLicenseList)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Unmarshal policyRule.LicenseName Failed will not scan license")
			return nil, errors.New("Unmarshal policyRule.LicenseName Failed will not scan license")
		}
	}

	customLicenseListMap := make(map[string]int)
	for k := range customLicenseList {
		customLicenseListMap[customLicenseList[k]] = 1
	}

	var result []model.PerLayerLicenseResult
	sum := 0
	for i := 1; i < len(layersFilePath); i++ {
		tmpRes, err := e.LicenseScan.ScanLayer(ctx, filepath.Join(layersFilePath[i], "layer.tar"))
		if err != nil {
			logging.GetLogger().Warn().Msgf("License Scan %v Error err:%v", layersFilePath[i], err)
		}
		tmpLayerResult := model.PerLayerLicenseResult{}
		tmpLayerResult.LayerDigest = layers[i]
		for k := range tmpRes {
			v, ok := customLicenseListMap[tmpRes[k].Name] // 由于这里开源协议没记录路径，所以做一次去重
			if ok {
				if v == 2 {
					continue
				}
				customLicenseListMap[tmpRes[k].Name]++
				tmpLayerResult.LicenseInfos = append(tmpLayerResult.LicenseInfos, tmpRes[k])
				sum++
			}
		}
		result = append(result, tmpLayerResult)
	}

	r := make(map[string]interface{})
	r["customFlag"] = 0
	if sum > 0 {
		r["customFlag"] = 1
	}
	r["result"] = result
	return r, nil
}

func init() {
	err := Register(executorScanLicenselName, newScanLicense)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("executorName", executorScanLicenselName).Msg("int executor err")
	}
}
func newScanLicense(config ExecutorConfig) (Executor, error) { // Open时调用
	e := &executorScanLicense{}
	e.LicenseScan = component.LicenseScan{}
	e.policy = config.Policy
	return e, nil
}

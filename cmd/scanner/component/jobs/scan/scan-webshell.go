package scan

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	executorScanWebshellName = "scan-webshell"
)

type ExecutorScanWebshell struct {
	// layerList     []string
	WebshellScan component.WebshellScan
}

func (e *ExecutorScanWebshell) Scan(ctx context.Context, param Param) (Artifact, error) {
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

	webshellAddr := global.ScannerOpts.WebShellServerAddr
	e.WebshellScan.WebshellAddr = fmt.Sprintf("%s/v1/php/detector", webshellAddr)

	resultWebshell := []model.PerLayerWebshellResult{}
	for i := 1; i < len(layers); i++ {
		tmpWebshellInfo := model.PerLayerWebshellResult{}
		tmpWebshellInfo.LayerDigest = layers[i]
		webshellInfos, err := e.WebshellScan.ScanLayer(context.Background(), layers[i], filepath.Join(layersFilePath[i], "layer.tar"))
		if err != nil {
			logging.GetLogger().Error().Err(err).Msgf("ScanWebshell %v failed", layers[i])
			continue
		}
		tmpWebshellInfo.WebShellInfos = append(tmpWebshellInfo.WebShellInfos, webshellInfos...)
		resultWebshell = append(resultWebshell, tmpWebshellInfo)
	}
	r := make(map[string]interface{})
	r["result"] = resultWebshell
	return r, nil
}

func init() {
	err := Register(executorScanWebshellName, newScanWebshell)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("executorName", executorScanWebshellName).Msg("int executor err")
	}
}
func newScanWebshell(config ExecutorConfig) (Executor, error) { // Open时调用
	e := &ExecutorScanWebshell{}
	e.WebshellScan = component.WebshellScan{}
	return e, nil
}

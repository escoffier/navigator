package scan

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	executorScanMaliciousName = "scan-malicious"
)

type ExecutorScanMalicious struct {
	// layerList     []string
	MaliciousScan component.MaliciousScan
}

func (e *ExecutorScanMalicious) scanMalicious(layer string, layerFilePath string, tmpvirus *model.PerLayerMaliciousResult, virus *[]model.PerLayerMaliciousResult) {
	virusInfos, err := e.MaliciousScan.ScanLayer(context.Background(), layer, filepath.Join(layerFilePath, "layer.tar"))
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("scan Virus %v failed", layer)
		return
	}
	if len(virusInfos) != 0 {
		tmpvirus.VirusInfos = append(tmpvirus.VirusInfos, virusInfos...)
		*virus = append(*virus, *tmpvirus)
	}
}

func (e *ExecutorScanMalicious) Scan(ctx context.Context, param Param) (Artifact, error) {
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

	virus := make([]model.PerLayerMaliciousResult, 0)
	scannerOrm := store.GetScannerDb()
	for i := 1; i < len(layers); i++ {
		tmpvirus := model.PerLayerMaliciousResult{}
		tmpvirus.LayerDigest = layers[i]
		logging.GetLogger().Info().Msgf("scan Viurs %v", layers[i])
		scanLayer, err := scannerOrm.QueryMaliciousResult(ctx, layers[i], time.Now())
		if err != nil {
			logging.GetLogger().Warn().Err(err).Msgf("Get scan Virus %v failed But will Scan twice", layers[i])
		} else if scanLayer.ID == 0 {
			e.scanMalicious(layers[i], layersFilePath[i], &tmpvirus, &virus)
		} else {
			if scanLayer.MaliciousInfoJSON != nil {
				err := json.Unmarshal(scanLayer.MaliciousInfoJSON, &scanLayer.MaliciousInfo)
				if err != nil {
					logging.GetLogger().Warn().Err(err).Msgf("Unmarshal scan Virus %v failed But will Scan twice", layers[i])
					e.scanMalicious(layers[i], layersFilePath[i], &tmpvirus, &virus)
				} else {
					for _, v := range scanLayer.MaliciousInfo {
						if strings.Contains(v.VirusInfo.VirusName, "Unix.Packed.Coinminer-6856324-0") {
							continue
						}
						if v.VirusInfo.FileName != "" {
							v.VirusInfo.FileName = strings.TrimLeft(v.VirusInfo.FileName, " ")
						}
						tmpvirus.VirusInfos = append(tmpvirus.VirusInfos, v.VirusInfo)
					}
					if len(tmpvirus.VirusInfos) != 0 {
						virus = append(virus, tmpvirus)
					}
				}
			}
		}
	}

	var webFrameRes []model.WebFrameInfo
	for i := 1; i < len(layers); i++ {
		res, err := e.MaliciousScan.ParseLayerTarWebFrame(filepath.Join(layersFilePath[i], "layer.tar"))
		if err != nil {
			continue
		}
		webFrameRes = append(webFrameRes, res...)
	}
	// logging.GetLogger().Info().Msgf("WebFramRes :%v", webFrameRes)
	// result := make([]model.Malicious, 0, len(virus))
	// for _, v := range virus {
	// 	tmpMalicious := model.Malicious{}
	// 	tmpMalicious.VirusInfo = v
	// 	result = append(result, tmpMalicious)
	// }

	r := make(map[string]interface{})
	r["result"] = virus
	r["webFrame"] = webFrameRes
	logging.GetLogger().Debug().Msgf("Virus detail : %v", virus)
	return r, nil
}

func init() {
	err := Register(executorScanMaliciousName, newScanMalicious)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("executorName", executorScanMaliciousName).Msg("int executor err")
	}
}
func newScanMalicious(config ExecutorConfig) (Executor, error) { //Open时调用
	e := &ExecutorScanMalicious{
		MaliciousScan: component.MaliciousScan{},
	}

	return e, nil
}

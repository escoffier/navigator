package scanjob

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/malicious"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var executorScanMaliciousSin *ExecutorScanMalicious

type ExecutorScanMalicious struct {
	MaliciousScan component.MaliciousScan
}

func (e *ExecutorScanMalicious) scanMalicious(layer string, layerFilePath string, tmpvirus *model.PerLayerMaliciousResult, virus *[]model.PerLayerMaliciousResult) {
	virusInfos, err := e.MaliciousScan.ScanLayer(context.Background(), layer, filepath.Join(layerFilePath, "layer.tar"))
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msgf("scan Virus %v failed", layer)
		return
	}
	if len(virusInfos) != 0 {
		tmpvirus.VirusInfos = append(tmpvirus.VirusInfos, virusInfos...)
		*virus = append(*virus, *tmpvirus)
	}
}

func (e *ExecutorScanMalicious) Scan(ctx context.Context, param Param) ([]model.PerLayerMaliciousResult, []model.WebFrameInfo, error) {
	virus := make([]model.PerLayerMaliciousResult, 0)
	var webFrameRes []model.WebFrameInfo

	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		return virus, webFrameRes, nil
	}
	layers, ok := param["layers"].([]string)
	if !ok {
		logging.Get().Error().Msg("miss 'layersFilePath' in parameter")
		return virus, webFrameRes, errors.New("miss 'layersFilePath' in parameter")
	}

	layersFilePath, ok := param["layersFilePath"].([]string)
	if !ok {
		logging.Get().Error().Msg("miss 'layersFilePath' in parameter")
		return virus, webFrameRes, errors.New("miss 'layersFilePath' in parameter")
	}

	for i := 1; i < len(layers); i++ {
		tmpvirus := model.PerLayerMaliciousResult{}
		tmpvirus.LayerDigest = layers[i]
		logging.Get().Info().Str("module", "imagescan").Msgf("scan Viurs %v", layers[i])
		e.scanMalicious(layers[i], layersFilePath[i], &tmpvirus, &virus)
	}

	for i := 1; i < len(layers); i++ {
		res, err := e.MaliciousScan.ParseLayerTarWebFrame(filepath.Join(layersFilePath[i], "layer.tar"))
		if err != nil {
			continue
		}
		webFrameRes = append(webFrameRes, res...)
	}

	logging.Get().Debug().Str("module", "imagescan").Msgf("Virus detail : %v", virus)
	return virus, webFrameRes, nil
}

func NewNScanMalicious(mqWriter mq.Writer) *ExecutorScanMalicious {
	if executorScanMaliciousSin != nil {
		return executorScanMaliciousSin
	}
	e := &ExecutorScanMalicious{
		MaliciousScan: component.MaliciousScan{
			MaliciousSrv: malicious.GetMaliciousServer(),
			MqWriter:     mqWriter,
		},
	}
	executorScanMaliciousSin = e
	return executorScanMaliciousSin
}

type MaliciousRes struct {
	Ma  []model.PerLayerMaliciousResult
	WF  []model.WebFrameInfo
	Err error
}

func (e *ExecutorScanMalicious) Task(ctx context.Context, param Param) chan MaliciousRes {
	out := make(chan MaliciousRes)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("ExecutorScanMalicious panic")
			}
		}()

		scan, infos, err := e.Scan(ctx, param)
		out <- MaliciousRes{
			Ma:  scan,
			WF:  infos,
			Err: err,
		}
	}()
	return out
}

// 病毒扫描可能卡死
func (e *ExecutorScanMalicious) DoTask(ctx context.Context, param Param, deepScan bool) MaliciousRes {
	if !deepScan {
		return MaliciousRes{
			Err: nil,
			Ma:  make([]model.PerLayerMaliciousResult, 0),
			WF:  make([]model.WebFrameInfo, 0),
		}
	}
	for {
		select {
		case <-ctx.Done():
			logging.Get().Error().Msg("scan malicious time out")
			return MaliciousRes{Err: fmt.Errorf("time out")}
		case res := <-e.Task(ctx, param):
			return res
		}
	}
}

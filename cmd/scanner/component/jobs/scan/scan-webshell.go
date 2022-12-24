package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	scannerWebshell "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-webshell"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	executorScanWebshellName = "scan-webshell"
)

type ExecutorScanWebshell struct {
	// layerList     []string
	WebshellScan component.WebshellScan
}

func (e *ExecutorScanWebshell) Scan(ctx context.Context, param Param) (Artifact, error) {
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		return nil, nil
	}
	digest, ok := param["digest"].(string)
	if !ok {
		logging.GetLogger().Error().Msg("miss 'digest' in parameter")
		return nil, errors.New("miss 'digest' in parameter")
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

	webshellAddr := global.ScannerOpts.WebShellServerAddr
	e.WebshellScan.WebshellAddr = fmt.Sprintf("%s/v1/php/detector", webshellAddr)

	mp := make(map[string][]scannermodel.WebshellFileInfo)
	digestPath := filepath.Join("/root", digest, fmt.Sprintf("%d", time.Now().UnixMicro()))
	if !util.FileExists(digestPath) {
		err := os.MkdirAll(digestPath, 0700)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Mkdir error")
		}
	}

	for i := 1; i < len(layers); i++ {
		tmpWebshellInfo := model.PerLayerWebshellResult{}
		tmpWebshellInfo.LayerDigest = layers[i]
		err := e.WebshellScan.ScanLayer(context.Background(), layers[i], filepath.Join(layersFilePath[i], "layer.tar"), digestPath, mp)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("ScanWebshell %v failed", layers[i])
			continue
		}
	}
	ctxTime, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	webshellSrv, err := scannerWebshell.GetService(ctxTime)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get webshellSrv too long")
		return nil, errors.New("get webshellSrv too long")
	}
	defer webshellSrv.BackServe()
	tblB, tblS, err := webshellSrv.ScanDir(digestPath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("hmWebshell Scan error")
		return nil, errors.New("hmWebshell Scan error")
	}
	webshellReuslt := e.arrangeResult(tblB, tblS, mp)
	logging.GetLogger().Info().Int64("fileNum", e.WebshellScan.TotalFileNum).Msg("webshell scan end")

	r := make(map[string]interface{})
	r["tmpPath"] = digestPath
	r["result"] = webshellReuslt
	return r, nil
}

func (e *ExecutorScanWebshell) arrangeResult(tblB []scannermodel.TblB, tblS []scannermodel.TblS, mp map[string][]scannermodel.WebshellFileInfo) scannermodel.WebshellResult {
	tmpRes := []scannermodel.WebshellFileInfo{}
	level := 2
	for _, v := range tblB {
		if files, ok := mp[v.Md5Hash]; ok {
			for _, file := range files {
				file.Description = v.Description
				file.Level = level
				file.Md5Hash = v.Md5Hash
				file.MaliciousData = v.MaliciousData
				tmpRes = append(tmpRes, file)
			}
		}
	}
	level = 1
	for _, v := range tblS {
		if files, ok := mp[v.Md5Hash]; ok {
			for _, file := range files {
				file.Description = v.Description
				file.Level = level
				file.Md5Hash = v.Md5Hash
				file.MaliciousData = v.MaliciousData
				tmpRes = append(tmpRes, file)
			}
		}
	}
	res := scannermodel.WebshellResult{FileInfos: tmpRes}
	return res
}

func init() {
	err := Register(executorScanWebshellName, newScanWebshell)
	if err != nil {
		logging.GetLogger().Err(err).Str("executorName", executorScanWebshellName).Msg("int executor err")
	}
}
func newScanWebshell(config ExecutorConfig) (Executor, error) { // Open时调用
	e := &ExecutorScanWebshell{}
	e.WebshellScan = component.WebshellScan{}
	return e, nil
}

package scanjob

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	scannerWebshell "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-webshell"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ExecutorScanWebshell struct {
	WebshellScan component.WebshellScan
}

func (e *ExecutorScanWebshell) Scan(ctx context.Context, param Param) ([]scannermodel.WebshellFileInfo, error) {
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		return nil, nil
	}
	digest, ok := param["digest"].(string)
	if !ok {
		logging.Get().Error().Msg("miss 'digest' in parameter")
		return nil, errors.New("miss 'digest' in parameter")
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

	webshellAddr := global.ScannerOpts.WebShellServerAddr
	e.WebshellScan.WebshellAddr = fmt.Sprintf("%s/v1/php/detector", webshellAddr)

	mp := make(map[string][]scannermodel.WebshellFileInfo)
	digestPath := filepath.Join("/root", digest, fmt.Sprintf("%d", time.Now().UnixMicro()))
	if !util.FileExists(digestPath) {
		err := os.MkdirAll(digestPath, 0700)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("Mkdir error")
		}
	}
	idMap := scannermodel.IDMap{UIDMap: make(map[int64]string), GIDMap: map[int64]string{}}
	for i := 1; i < len(layers); i++ {
		tmpWebshellInfo := model.PerLayerWebshellResult{}
		tmpWebshellInfo.LayerDigest = layers[i]
		err := e.WebshellScan.ScanLayer(context.Background(), layers[i], filepath.Join(layersFilePath[i], "layer.tar"), digestPath, mp, idMap)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msgf("ScanWebshell %v failed", layers[i])
			continue
		}
	}
	ctxTime, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	webshellSrv, err := scannerWebshell.GetService(ctxTime)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("get webshellSrv too long")
		return nil, errors.New("get webshellSrv too long")
	}
	defer webshellSrv.BackServe()
	tblB, tblS, err := webshellSrv.ScanDir(digestPath)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("hmWebshell Scan error")
		return nil, errors.New("hmWebshell Scan error")
	}
	webshellReuslt := e.arrangeResult(tblB, tblS, mp)
	logging.Get().Info().Str("module", "imagescan").Int64("fileNum", e.WebshellScan.TotalFileNum).Msg("webshell scan end")
	e.PaeseUGName(webshellReuslt, idMap)
	return webshellReuslt.FileInfos, nil
}

func (e *ExecutorScanWebshell) PaeseUGName(result scannermodel.WebshellResult, idMap scannermodel.IDMap) {
	for k, v := range result.FileInfos {
		if vv, ok := idMap.UIDMap[v.UID]; ok {
			result.FileInfos[k].UName = vv
		}
		if vv, ok := idMap.GIDMap[v.GID]; ok {
			result.FileInfos[k].GName = vv
		}
	}
}

func (e *ExecutorScanWebshell) arrangeResult(tblB []scannermodel.TblB, tblS []scannermodel.TblS,
	mp map[string][]scannermodel.WebshellFileInfo) scannermodel.WebshellResult {
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

var executorScanWebshellSin *ExecutorScanWebshell

func NewScanWebshell(mqWriter mq.Writer) *ExecutorScanWebshell {
	if executorScanWebshellSin != nil {
		return executorScanWebshellSin
	}
	e := &ExecutorScanWebshell{WebshellScan: component.WebshellScan{
		MqWriter: mqWriter,
	}}
	executorScanWebshellSin = e
	return executorScanWebshellSin
}

type WebshellRes struct {
	WB  []scannermodel.WebshellFileInfo
	Err error
}

func (e *ExecutorScanWebshell) Task(ctx context.Context, param Param) chan WebshellRes {
	out := make(chan WebshellRes)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("ExecutorScanMalicious panic")
			}
		}()

		wb, err := e.Scan(ctx, param)

		out <- WebshellRes{
			WB:  wb,
			Err: err,
		}
	}()
	return out
}

func (e *ExecutorScanWebshell) DoTask(ctx context.Context, param Param, deepScan bool) WebshellRes {
	if !deepScan {
		return WebshellRes{
			Err: nil,
			WB:  make([]scannermodel.WebshellFileInfo, 0),
		}
	}

	for {
		select {
		case <-ctx.Done():
			logging.Get().Error().Msg("scan webshell time out")
			return WebshellRes{Err: fmt.Errorf("time out")}
		case res := <-e.Task(ctx, param):
			return res
		}
	}
}

package scanwebshell

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

type WebshellSrv struct {
	dal store.WebshellDal
}

func NewWebshellSrv(dal store.WebshellDal) WebshellSrv {
	return WebshellSrv{dal: dal}
}

func (w *WebshellSrv) GetPath(path string) (string, string) {
	index := strings.LastIndex(path, "/")
	if index == -1 {
		return "/", path
	}
	return path[0 : index+1], path[index+1:]
}

func (w *WebshellSrv) ListWebshells(ctx *gin.Context, params store.SearchWebshellParam, filter model.Filter) ([]scannermodel.WebshellList, int64, error) {
	webshellImges, _, err := w.dal.SearchWebshellImage(ctx, params, filter)
	if err != nil {
		logging.Get().Err(err).Msg("SearchWebshellImage error")
		return nil, 0, err
	}
	for k := range webshellImges {
		params.UUIDS = append(params.UUIDS, webshellImges[k].UniqueTarget)
	}
	if len(params.UUIDS) == 0 {
		return nil, 0, nil
	}
	webshells, cnt, err := w.dal.SearchWebshell(ctx, params, filter)
	if err != nil {
		logging.Get().Err(err).Msg("SearchWebshell error")
		return nil, 0, err
	}
	res := []scannermodel.WebshellList{}
	for _, v := range webshells {
		tmp := scannermodel.WebshellList{}
		path, name := w.GetPath(v.FileName)
		tmp.FileMd5 = v.FileMd5
		tmp.FileNmae = name
		tmp.FilePath = path
		tmp.Level = v.Level
		tmp.UUID = v.UniqueID
		tmp.Download = w.IsDownload(tmp.FileMd5)
		if tmp.Download == 0 {
			if v.FileSize > scannermodel.WebshellSize {
				tmp.Tip = "文件超过 10M，暂不支持下载"
			} else {
				tmp.Tip = "文件已清理，请重新扫描镜像"
			}
		}
		res = append(res, tmp)
	}
	return res, cnt, nil
}

func (w *WebshellSrv) GetDetail(ctx *gin.Context, params store.SearchWebshellParam, filter model.Filter) (scannermodel.WebshellDetail, error) {
	webshells, _, err := w.dal.SearchWebshell(ctx, params, filter)
	if err != nil {
		logging.Get().Err(err).Msg("search webshell error")
		return scannermodel.WebshellDetail{}, err
	}
	if len(webshells) == 0 {
		return scannermodel.WebshellDetail{}, nil
	}
	res := scannermodel.WebshellDetail{}
	path, _ := w.GetPath(webshells[0].FileName)
	res.FilePath = path
	lastIndex := strings.LastIndex(webshells[0].FileName, ".")
	if lastIndex != -1 {
		res.Ext = webshells[0].FileName[lastIndex+1:]
	}
	des := strings.Split(webshells[0].Description, "-")
	res.FileMode = webshells[0].FileMode
	res.FileSize = webshells[0].FileSize
	res.LastModify = webshells[0].FileModtime
	if des != nil {
		res.Detail = des[0]
	}
	if len(des) > 1 {
		res.Suggestion = des[1]
	}
	if res.Suggestion == "" {
		if webshells[0].Level == "maybe" {
			res.Suggestion = "建议人工确认后处置"
		} else {
			res.Suggestion = "立即处置"
		}
	}
	tmpCode := []scannermodel.BeforeDecode{}
	err = json.Unmarshal([]byte(webshells[0].MaliciousData), &tmpCode)
	if err != nil {
		logging.Get().Err(err).Msgf("get maliciousData error")
	} else {
		for k := range tmpCode {
			decode, err := base64.StdEncoding.DecodeString(tmpCode[k].Data)
			if err != nil {
				logging.Get().Err(err).Msg("decode base64 error")
				continue
			}
			code := scannermodel.WebshellCode{}
			code.Data = decode
			logging.Get().Info().Msgf("code is :%s", string(decode))
			code.Offset = tmpCode[k].Offset
			res.Code = append(res.Code, code)
		}
	}
	ws, _, err := w.dal.SearchWebshell(ctx, store.SearchWebshellParam{Md5: webshells[0].FileMd5}, model.Filter{})
	uuids := []uint64{}
	for k := range ws {
		uuids = append(uuids, ws[k].UniqueID)
	}
	logging.Get().Info().Msgf("uuid = %v,file_md5=%s", uuids, webshells[0].FileMd5)
	webshellImages, _, err := w.dal.SearchWebshellImage(ctx, store.SearchWebshellParam{UTarget: uuids}, filter)
	mp := make(map[int64]struct{}, 0)
	for k := range webshellImages {
		mp[webshellImages[k].ImageID] = struct{}{}
	}
	images := []int64{}
	for k, _ := range mp {
		images = append(images, k)
	}
	logging.Get().Info().Msgf("webshell images:%v", images)
	imagesName, err := w.dal.SearchRegistry(ctx, images)
	logging.Get().Info().Msgf("imagesName :%v", imagesName)
	if err != nil {
		logging.Get().Err(err).Msg("search registry error")
	} else {
		res.Images = imagesName
	}
	return res, nil
}

func (w *WebshellSrv) GetCode(md5 string, uuid uint64) ([]scannermodel.ProblemCode, error) {
	filePath := filepath.Join(global.ScannerOpts.PvcPath, "webshell", md5)
	datas := [][]byte{}
	if util.FileExists(filePath) {
		data, err := os.ReadFile(filePath)
		if err != nil {
			logging.Get().Err(err).Msg("read file error")
			//response.JSONError(ctx, fmt.Errorf("read file error"))
			return nil, err
		}
		datas = bytes.Split(data, []byte{'\n'})
	}
	webshell, _, err := w.dal.SearchWebshell(context.Background(), store.SearchWebshellParam{UUIDS: []uint64{uuid}}, model.Filter{})
	if err != nil {
		logging.Get().Err(err).Msg("get code error")
		return nil, err
	}
	tmpCode := []scannermodel.BeforeDecode{}
	decodeCode := []scannermodel.WebshellCode{}
	err = json.Unmarshal([]byte(webshell[0].MaliciousData), &tmpCode)
	if err != nil {
		logging.Get().Err(err).Msgf("get maliciousData error")
	} else {
		for k := range tmpCode {
			if strings.Contains(tmpCode[k].Name, "ssdeep") {
				continue
			}
			decode, err := base64.StdEncoding.DecodeString(tmpCode[k].Data)
			if err != nil {
				logging.Get().Err(err).Msg("decode base64 error")
				continue
			}
			code := scannermodel.WebshellCode{}
			code.Data = decode
			code.Offset = tmpCode[k].Offset
			decodeCode = append(decodeCode, code)
		}
	}
	res := []scannermodel.ProblemCode{}
	lenth := 0
	for k := range datas {
		tmpPro := scannermodel.ProblemCode{}
		tmpPro.Data = datas[k]
		for kk, v := range decodeCode {
			if len(tmpPro.Problem) > 0 {
				break
			}
			if v.Offset >= int64(lenth) && v.Offset <= int64(lenth)+int64(len(datas[k])) {
				byteData := []byte(v.Data)
				cutLen := int64(lenth) + int64(len(datas[k])) - v.Offset
				proLen := v.Offset + int64(len(byteData))
				if proLen > int64(lenth)+int64(len(datas[k])) {
					proData := byteData[:cutLen+1]
					tmpPro.Problem = append(tmpPro.Problem, string(proData))
					if cutLen+1 < int64(len(byteData)) {
						decodeCode[kk].Data = byteData[cutLen+1:]
						decodeCode[kk].Offset += cutLen + 1
					}
				} else {
					tmpPro.Problem = append(tmpPro.Problem, string(v.Data))
				}
			}
		}
		lenth += len(datas[k]) + 1 //补足换行
		if len(tmpPro.Problem) > 0 {
			str := base64.StdEncoding.EncodeToString([]byte(tmpPro.Problem[0]))
			tmpPro.Problem[0] = str
		}
		res = append(res, tmpPro)
	}
	return res, err
}

func (w *WebshellSrv) IsDownload(md5 string) int {
	path := filepath.Join(global.ScannerOpts.PvcPath, "webshell", md5)
	if util.FileExists(path) {
		return 1
	}
	return 0
}

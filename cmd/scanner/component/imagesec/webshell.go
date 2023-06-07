package imagesec

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type WebshellService interface {
	GetWebshellContent(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]imagesecModel.WebshellContent, error)
	SearchWebshell(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.WebshellView, int64, error)
	GetWebshellFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]byte, error)
}

type WebshellSrv struct {
	scanResultDal imagesecStore.ScanResultDal
}

func (s *WebshellSrv) SearchWebshell(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]*imagesecModel.WebshellView, int64, error) {
	webshell, cnt, err := s.scanResultDal.SearchWebshell(ctx, param)
	if err != nil {
		logging.Get().Err(err).Uint64("uniqueID", param.UniqueIds[0]).Msg("SearchWebshell")
		return nil, 0, err
	}
	ans := make([]*imagesecModel.WebshellView, 0)

	for i := range webshell {
		ans = append(ans, webshell[i].ToWebshellView())
	}
	return ans, cnt, nil
}

func (s *WebshellSrv) GetWebshellContent(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]imagesecModel.WebshellContent, error) {
	if len(param.UniqueIds) == 0 {
		return nil, fmt.Errorf("not get webshell uniqueID")
	}

	webshell, _, err := s.scanResultDal.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: param.UniqueIds})
	if err != nil {
		logging.Get().Err(err).Uint64("uniqueID", param.UniqueIds[0]).Msg("SearchWebshell")
		return nil, err
	}
	if len(webshell) == 0 {
		return nil, fmt.Errorf("not get webshell:%d", param.UniqueIds[0])
	}
	ws := webshell[0].ToWebshellView()

	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, ws.MD5)

	if !util.FileExists(filename) {
		logging.Get().Error().Str("filename", filename).Msg("webshell file has cleaned")
		return nil, fmt.Errorf("webshell file has cleaned")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		logging.Get().Err(err).Str("file", filename).Msg("GetWebshellFile read file")
		return nil, err
	}
	data := bytes.Split(content, []byte{'\n'})

	res := make([]imagesecModel.WebshellContent, 0)
	var offset int64
	for i := range data {
		line := imagesecModel.WebshellContent{
			Line:    string(data[i]),
			Problem: make([]string, 0),
		}
		for j := range ws.Code {
			po := ws.Code[j]
			if !po.Parsed {
				offset += int64(len(data[i]))
				continue
			}
			if po.Offset >= offset && po.Offset <= offset+int64(len(data[i])) && strings.Contains(line.Line, po.Data) {
				line.Problem = append(line.Problem, po.Data)
			}
		}
		offset += int64(len(data[i]))

		res = append(res, line)
	}
	return res, nil
}

func (s *WebshellSrv) GetWebshellFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]byte, error) {
	if len(param.UniqueIds) == 0 {
		return nil, fmt.Errorf("not get webshell uniqueID")
	}

	webshell, _, err := s.scanResultDal.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: param.UniqueIds})
	if err != nil {
		logging.Get().Err(err).Uint64("uniqueID", param.UniqueIds[0]).Msg("SearchWebshell")
		return nil, err
	}
	if len(webshell) == 0 {
		return nil, fmt.Errorf("not get webshell:%d", param.UniqueIds[0])
	}
	ws := webshell[0].ToWebshellView()

	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, ws.MD5)

	if !util.FileExists(filename) {
		logging.Get().Error().Str("filename", filename).Msg("webshell file has cleaned")
		return nil, fmt.Errorf("webshell file has cleaned")
	}
	// 这里不直接返回是因为：windows会报木马病毒，然后自动删除
	data, err := ZipWebshellFile(*ws)
	if err != nil {
		logging.Get().Err(err).Str("file", filename).Msg("GetWebshellFile read file")
		return nil, err
	}
	return data, nil
}

// 把多个excel打包成一个zip文件返回,
func ZipWebshellFile(wb imagesecModel.WebshellView) ([]byte, error) {

	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, wb.MD5)

	content, err := os.ReadFile(filename)
	if err != nil {
		logging.Get().Err(err).Str("file", filename).Msg("GetWebshellFile read file")
		return nil, err
	}
	b := new(bytes.Buffer)
	zw := zip.NewWriter(b)
	logging.Get().Info().Str("filename", wb.Filename).Str("md5", wb.MD5).Msg("get webshell file")

	hdr := zip.FileHeader{Name: wb.Filename}
	w, err := zw.CreateHeader(&hdr)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(content)
	_, err = io.Copy(w, reader)
	if err != nil {
		return nil, err
	}
	if err := zw.Flush(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func NewWebshellSrv(
	scanResultDal imagesecStore.ScanResultDal,
) *WebshellSrv {
	return &WebshellSrv{scanResultDal: scanResultDal}
}

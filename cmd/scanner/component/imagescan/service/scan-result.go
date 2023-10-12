package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"

	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanResultService interface {
	SearchVuln(ctx context.Context, param imagesecModel.ApiSearchVulnParam) ([]*imagesecModel.VulnView, int64, error)
	SearchPkg(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.Pkg, int64, error)
	SearchLicense(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.License, error)
	SearchSensitive(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.SensitiveFile, error)
	SearchMalware(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.Malware, error)
	VulnOverview(ctx context.Context, param imagesecModel.VulnOverviewParam) (*imagesecModel.VulnOverview, error) // 默认查在线
	GetWebshellContent(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]imagesecModel.WebshellContent, error)
	SearchWebshell(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.WebshellView, int64, error)

	GetWebshellFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]byte, *imagesecModel.WebshellView, error)
	GetSensitiveFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]byte, *imagesecModel.SensitiveFile, error)
	GetMalwareFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]byte, *imagesecModel.Malware, error)
	GetLicenseFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]byte, *imagesecModel.License, error)
}

type ScanResultSrv struct {
	ScanResultDal imagesecStore.ScanResultDal
	vulnOverview  *VulnOverView
	imageCacheDal imagesecStore.ImageCacheDal
}

var scanResultSrv *ScanResultSrv

func NewScanResultSrv(
	scanResultDal imagesecStore.ScanResultDal,
	imageCacheDal imagesecStore.ImageCacheDal,
) *ScanResultSrv {
	if scanResultSrv != nil {
		return scanResultSrv
	}
	s := &ScanResultSrv{ScanResultDal: scanResultDal, imageCacheDal: imageCacheDal}
	s.vulnOverview = NewVulnOverView()

	s.vulnOverviewHelper(context.Background())

	scanResultSrv = s

	return scanResultSrv
}

func (s *ScanResultSrv) SearchVuln(ctx context.Context, param imagesecModel.ApiSearchVulnParam) ([]*imagesecModel.VulnView, int64, error) {
	dalParam := param.ToDaoSearchVulnParam()

	vuln, cnt, err := s.ScanResultDal.SearchVuln(ctx, dalParam)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchVuln")
		return nil, 0, scani18.SearchVuln(err)
	}
	vulns := make([]*imagesecModel.VulnView, len(vuln))
	for i := range vuln {
		vulns[i] = vuln[i].GenVulnView()
	}

	return vulns, cnt, nil
}

func (s *ScanResultSrv) SearchPkg(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.Pkg, int64, error) {
	if param.VulnUniqueID > 0 {
		vuln, _, err := s.ScanResultDal.SearchVuln(ctx, imagesecModel.SearchVulnDalParam{VulnUniqueID: param.VulnUniqueID})
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchVuln")
			return nil, 0, scani18.SearchPKG(err)
		}
		if len(vuln) == 0 {
			return []*imagesecModel.Pkg{}, 0, nil
		}
		param.VulnName = vuln[0].Name
	}

	pkg, cnt, err := s.ScanResultDal.SearchPkg(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchPkg")
		return nil, 0, scani18.SearchPKG(err)
	}
	return pkg, cnt, nil
}

func (s *ScanResultSrv) SearchLicense(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.License, error) {
	data, _, err := s.ScanResultDal.SearchLicense(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchVuln")
		return nil, scani18.GetLicenseInfo(err)
	}
	if len(data) == 0 {
		return nil, scani18.GetLicenseInfo(nil)
	}
	return data, nil
}

func (s *ScanResultSrv) SearchMalware(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.Malware, error) {
	data, _, err := s.ScanResultDal.SearchMalware(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchVuln")
		return nil, scani18.GetMalwareInfo(err)
	}
	if len(data) == 0 {
		return nil, scani18.GetMalwareInfo(nil)
	}
	return data, nil
}

func (s *ScanResultSrv) SearchSensitive(ctx context.Context, param imagesecModel.ScanResultSearchParam) ([]*imagesecModel.SensitiveFile, error) {
	data, _, err := s.ScanResultDal.SearchSensitive(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("param", param).Msg("SearchVuln")
		return nil, scani18.GetLicenseInfo(err)
	}
	if len(data) == 0 {
		return nil, scani18.GetSensitiveInfo(nil)
	}
	return data, nil
}

func (s *ScanResultSrv) SearchWebshell(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]*imagesecModel.WebshellView, int64, error) {
	webshell, cnt, err := s.ScanResultDal.SearchWebshell(ctx, param)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Uint64("uniqueID", param.UniqueIds[0]).Msg("SearchWebshell")
		return nil, 0, err
	}
	ans := make([]*imagesecModel.WebshellView, 0)

	for i := range webshell {
		ans = append(ans, webshell[i].ToWebshellView())
	}
	return ans, cnt, nil
}

func (s *ScanResultSrv) GetWebshellContent(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]imagesecModel.WebshellContent, error) {
	if len(param.UniqueIds) == 0 {
		return nil, fmt.Errorf("not get webshell uniqueID")
	}

	webshell, _, err := s.ScanResultDal.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: param.UniqueIds})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Uint64("uniqueID", param.UniqueIds[0]).Msg("SearchWebshell")
		return nil, err
	}
	if len(webshell) == 0 {
		return nil, fmt.Errorf("not get webshell:%d", param.UniqueIds[0])
	}
	ws := webshell[0].ToWebshellView()

	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, ws.MD5)

	if !util.FileExists(filename) {
		logging.Get().Error().Str("filename", filename).Msg("file has cleaned")
		return nil, fmt.Errorf("file has cleaned")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("file", filename).Msg("GetWebshellFile read file")
		return nil, err
	}
	data := bytes.Split(content, []byte{'\n'})

	res := make([]imagesecModel.WebshellContent, 0)
	var offset int64

	for lineNo := range data {
		line := imagesecModel.WebshellContent{
			Line:    string(data[lineNo]),
			Problem: make([]string, 0),
		}
		for j := range ws.Code {
			po := ws.Code[j]
			if !po.Parsed {
				continue
			}
			if po.Offset >= offset && po.Offset <= offset+int64(len(data[lineNo])) && strings.Contains(line.Line, po.Data) {
				line.Problem = append(line.Problem, po.Data)
			}
		}
		offset += int64(len(data[lineNo])) + 1 // 注意：\n 也算一个字符，要把换行的 \n 加上

		res = append(res, line)
	}
	return res, nil
}

func (s *ScanResultSrv) GetWebshellFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]byte, *imagesecModel.WebshellView, error) {
	if len(param.UniqueIds) == 0 {
		return nil, nil, fmt.Errorf("not get webshell uniqueID")
	}

	webshell, _, err := s.ScanResultDal.SearchWebshell(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: param.UniqueIds})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Uint64("uniqueID", param.UniqueIds[0]).Msg("SearchWebshell")
		return nil, nil, err
	}
	if len(webshell) == 0 {
		return nil, nil, fmt.Errorf("not get webshell:%d", param.UniqueIds[0])
	}
	ws := webshell[0].ToWebshellView()

	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, ws.MD5)

	if !util.FileExists(filename) {
		logging.Get().Error().Str("filename", filename).Msg("file has cleaned")
		return nil, nil, fmt.Errorf("file has cleaned")
	}
	// 这里不直接返回是因为：windows会报木马病毒，然后自动删除
	data, err := ZipFile(ZipFileMate{MD5: ws.MD5, Filename: ws.Filename})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("file", filename).Msg("GetWebshellFile read file")
		return nil, nil, err
	}
	return data, ws, nil
}

func (s *ScanResultSrv) GetSensitiveFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]byte, *imagesecModel.SensitiveFile, error) {
	if len(param.UniqueIds) == 0 {
		return nil, nil, fmt.Errorf("not get res uniqueID")
	}

	res, _, err := s.ScanResultDal.SearchSensitive(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: param.UniqueIds})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Uint64("uniqueID", param.UniqueIds[0]).Msg("GetSensitiveFile")
		return nil, nil, err
	}
	if len(res) == 0 {
		return nil, nil, scani18.NotGetFile(nil)
	}
	ws := res[0]
	if ws.MD5 == "" {
		return nil, nil, scani18.NotGetFile(nil)
	}
	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, ws.MD5)

	if !util.FileExists(filename) {
		logging.Get().Error().Str("filename", filename).Msg("GetSensitiveFile file has cleaned")
		return nil, nil, scani18.NotGetFile(nil)
	}
	// 这里不直接返回是因为：windows会报木马病毒，然后自动删除
	data, err := ZipFile(ZipFileMate{MD5: ws.MD5, Filename: ws.Filename})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("file", filename).Msg("GetSensitiveFile read file")
		return nil, nil, scani18.NotGetFile(err)
	}
	return data, ws, nil
}

func (s *ScanResultSrv) GetMalwareFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]byte, *imagesecModel.Malware, error) {
	if len(param.UniqueIds) == 0 {
		return nil, nil, fmt.Errorf("not get webshell uniqueID")
	}

	webshell, _, err := s.ScanResultDal.SearchMalware(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: param.UniqueIds})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Uint64("uniqueID", param.UniqueIds[0]).Msg("GetMalwareFile")
		return nil, nil, err
	}
	if len(webshell) == 0 {
		return nil, nil, scani18.NotGetFile(nil)
	}
	ws := webshell[0]

	if ws.Hash == "" {
		return nil, nil, scani18.NotGetFile(nil)
	}

	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, ws.Hash)

	if !util.FileExists(filename) {
		logging.Get().Error().Str("filename", filename).Msg("GetMalwareFile file has cleaned")
		return nil, nil, scani18.NotGetFile(nil)
	}
	// 这里不直接返回是因为：windows会报木马病毒，然后自动删除
	data, err := ZipFile(ZipFileMate{MD5: ws.Hash, Filename: ws.Filename})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("file", filename).Msg("GetMalwareFile read file")
		return nil, ws, scani18.NotGetFile(err)
	}
	return data, ws, nil
}

func (s *ScanResultSrv) GetLicenseFile(ctx context.Context, param imagesecModel.ScanResultSearchParam) (
	[]byte, *imagesecModel.License, error) {
	if len(param.UniqueIds) == 0 {
		return nil, nil, fmt.Errorf("not get webshell uniqueID")
	}

	webshell, _, err := s.ScanResultDal.SearchLicense(ctx, imagesecModel.ScanResultSearchParam{UniqueIds: param.UniqueIds})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Uint64("uniqueID", param.UniqueIds[0]).Msg("GetLicenseFile")
		return nil, nil, err
	}
	if len(webshell) == 0 {
		return nil, nil, scani18.NotGetFile(nil)
	}
	ws := webshell[0]
	if ws.MD5 == "" {
		return nil, nil, scani18.NotGetFile(nil)
	}
	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, ws.MD5)

	if !util.FileExists(filename) {
		logging.Get().Error().Str("filename", filename).Msg("GetLicenseFile file has cleaned")
		return nil, nil, scani18.NotGetFile(nil)
	}
	// 这里不直接返回是因为：windows会报木马病毒，然后自动删除
	data, err := ZipFile(ZipFileMate{MD5: ws.MD5, Filename: ws.Filename})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("file", filename).Msg("GetLicenseFile read file")
		return nil, ws, scani18.NotGetFile(err)
	}
	return data, ws, nil
}

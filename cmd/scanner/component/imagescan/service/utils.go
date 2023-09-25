package service

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ZipFileMate struct {
	MD5      string `json:"md5"`
	Filename string `json:"filename"`
	Data     []byte
}

func ZipFile(wb ZipFileMate) ([]byte, error) {

	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, wb.MD5)

	content, err := os.ReadFile(filename)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("file", filename).Msg("GetWebshellFile read file")
		return nil, err
	}
	b := new(bytes.Buffer)
	zw := zip.NewWriter(b)
	logging.Get().Info().Str("module", "imagescan").Str("filename", wb.Filename).Str("md5", wb.MD5).Msg("get file")

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

func ZipLicenseFile(wb ZipFileMate) ([]byte, error) {

	b := new(bytes.Buffer)
	zw := zip.NewWriter(b)

	hdr := zip.FileHeader{Name: wb.Filename}
	w, err := zw.CreateHeader(&hdr)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(wb.Data)
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

func addVulnOver(res *imagesecModel.VulnOverview, severity int, cnt int64) {
	res.VulnTotal += cnt
	switch severity {
	case imagesecModel.SeverityCriticalInt:
		res.Severity.Critical = cnt
	case imagesecModel.SeverityHighInt:
		res.Severity.High = cnt
	case imagesecModel.SeverityMediumInt:
		res.Severity.Medium = cnt
	case imagesecModel.SeverityLowInt:
		res.Severity.Low = cnt
	case imagesecModel.SeverityUnknownInt:
		res.Severity.Unknown = cnt
	}
}

package license

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	dockerarchive "github.com/docker/docker/pkg/archive"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type ScanLicense struct {
	Log *scannerUtils.LogEvent
}

func NewScanLicense() *ScanLicense {
	s := &ScanLicense{
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ScanLicense"),
			scannerUtils.WithModule(consts.ModuleImageMeta)),
	}
	return s
}

func (s *ScanLicense) ScanLocalFile(ctx context.Context, pre *imagesecTypes.PrepareScan) imagesecTypes.ScanJobResult {
	result := imagesecTypes.ScanJobResult{}
	for i := range pre.Layers {
		ly := pre.Layers[i]
		err := filepath.Walk(ly.LayerFilePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				s.Log.Err(err).Interface("layer", ly).Msg("ScanLocalFile walk")
				return err
			}
			if !scannerUtils.CommonFilter(info) {
				return nil
			}

			fd, err := os.Open(path)
			if err != nil {
				s.Log.Err(err).Str("file", path).Msg("ScanLicense open")
				return nil
			}
			defer func() { _ = fd.Close() }()
			license, _, err := s.getLicense(ctx, path, fd)
			if err != nil {
				return err
			}
			for j := range license {
				license[j].Layer = ly.Digest
			}
			result.License = append(result.License, license...)
			return nil
		})
		if err != nil {
			s.Log.Err(err).Msg("License Scan")
		}
	}

	return result
}

func (s *ScanLicense) ScanTarFile(ctx context.Context, pre *imagesecTypes.PrepareScan) []imagesecTypes.ScanJobResult {

	result := make([]imagesecTypes.ScanJobResult, 0)

	for i := range pre.Layers {
		ly := pre.Layers[i]

		res := imagesecTypes.ScanJobResult{
			Layer: ly.Digest,
			Issue: imagesecModel.LicenseCacheData,
		}

		if pre.Subtask.LicenseCache.In(ly.Digest) {
			res.InCache = true
			result = append(result, res)
			continue
		}

		lic, kaf, err := s.scanTarLayer(ctx, ly)
		if err != nil {
			s.Log.Err(err).Interface("layer", ly).Msg("scanTarLayer")
			res.Errors = append(res.Errors, err)
			result = append(result, res)
			continue
		}

		for j := range lic {
			lic[j].Layer = ly.Digest
		}
		for j := range kaf {
			kaf[j].Layer = ly.Digest
		}

		res.License = append(res.License, lic...)

		res.SaveFileToKafka = append(res.SaveFileToKafka, kaf...)

		res.Scanned = true

		result = append(result, res)
	}
	return result
}

func (s *ScanLicense) ImageScan(ctx context.Context, pre *imagesecTypes.PrepareScan) []imagesecTypes.ScanJobResult {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "ScanLicense").Msg("scan job start")
	defer s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "ScanLicense").Msg("scan job end")

	// if pre.Subtask.DeepScan {
	// 	return s.ScanLocalFile(ctx, pre)
	// }

	// 在开启动深度扫描时为啥不用文件扫描呢：
	// 因为有 WhiteOut 的机制存在，会导致两种方式扫描的结果可能不一致
	// 用文件扫描是正确的，用tar包是错的，因为还没有处理 whiteOut

	return s.ScanTarFile(ctx, pre)
}

func (s *ScanLicense) scanTarLayer(ctx context.Context, ly *imagesecTypes.ImageLayer) ([]imagesecTypes.License, []imagesecTypes.SaveFileToKafka, error) {
	sess := make([]imagesecTypes.License, 0)
	kaf := make([]imagesecTypes.SaveFileToKafka, 0)

	file, err := os.Open(ly.OriginalTarFile)
	if err != nil {
		return sess, kaf, err
	}
	defer func() { _ = file.Close() }()
	// 不能使用自带的包直接解压，一定得有这一步
	decompressStreamReader, err := dockerarchive.DecompressStream(file)
	if err != nil {
		return sess, kaf, err
	}

	defer func() { _ = decompressStreamReader.Close() }()
	tarReader := tar.NewReader(decompressStreamReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.Log.Err(err).Str("layer", ly.OriginalTarFile).Msg("scanTarLayer")
			return sess, kaf, err
		}
		fi := header.FileInfo()
		//
		if !scannerUtils.CommonFilter(fi) {
			continue
		}

		// header.Name 是全称，但是没有最开始的 /
		// fi.Name()是最后一级的文件名
		lic, kafs, err := s.getLicense(ctx, header.Name, tarReader)
		if err != nil {
			s.Log.Err(err).Str("file", header.Name).Msg("scanTarLayer")
			return sess, kaf, err
		}
		for j := range lic {
			lic[j].Layer = ly.Digest
		}
		for i := range kafs {
			kafs[i].Layer = ly.Digest
		}

		sess = append(sess, lic...)
		kaf = append(kaf, kafs...)
	}
	return sess, kaf, nil
}

func (s *ScanLicense) getLicense(ctx context.Context, filename string, reader io.Reader) ([]imagesecTypes.License, []imagesecTypes.SaveFileToKafka, error) {

	res := make([]imagesecTypes.License, 0)
	kaf := make([]imagesecTypes.SaveFileToKafka, 0)
	if !strings.Contains(strings.ToUpper(filename), "LICENSE") {
		return res, kaf, nil
	}

	fileByte, err := io.ReadAll(reader)
	if err != nil {
		return res, kaf, err
	}
	if len(fileByte) == 0 {
		return res, kaf, nil
	}
	li := GetLicenseName(fileByte)
	if li == "" {
		return res, kaf, nil
	}

	lic := imagesecTypes.License{
		Name:     li,
		Filename: filename,
		MD5:      scannerUtils.GetContentMd5(fileByte),
	}
	ka := imagesecTypes.SaveFileToKafka{
		FileMd5:  scannerUtils.GetContentMd5(fileByte),
		Data:     fileByte,
		Filename: filename,
	}
	res = append(res, lic)
	kaf = append(kaf, ka)

	return res, kaf, nil
}

func GetLicenseName(data []byte) string {
	con := string(data)

	if strings.Contains(con, "New BSD License") {
		return "BSD 3-Clause"
	}

	if strings.Contains(con, "GNU GENERAL PUBLIC LICENSE") {
		return "GPL"
	}

	if strings.Contains(con, "BSD 2-Clause") {
		return "BSD 2-Clause"
	}

	if strings.Contains(con, "MIT") {
		return "MIT"
	}

	if strings.Contains(con, "Mozilla Public License Version") {
		return "MPT"
	}

	if strings.Contains(con, "Apache License") {
		return "Apache License"
	}

	if strings.Contains(con, "Permission to use, copy, modify") {
		return "ISC"
	}
	return ""
}

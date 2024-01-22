package sensitive

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	dockerarchive "github.com/docker/docker/pkg/archive"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanSensitive struct {
	RegexpMap map[string]*regexp.Regexp
	Rule      map[string]*imagesecModel.SensitiveRule
	Log       *scannerUtils.LogEvent
}

func NewScanSensitiveSrv() (*ScanSensitive, error) {
	s := &ScanSensitive{
		RegexpMap: make(map[string]*regexp.Regexp),
		Rule:      make(map[string]*imagesecModel.SensitiveRule),
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ScanSensitive"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}

	if err := s.SetDefaultRule(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *ScanSensitive) ScanTarFile(ctx context.Context, prep *imagesecTypes.PrepareScan) []imagesecTypes.ScanJobResult {
	result := make([]imagesecTypes.ScanJobResult, 0)
	for i := range prep.Layers {
		ly := prep.Layers[i]

		res := imagesecTypes.ScanJobResult{
			Layer:     ly.Digest,
			DBVersion: prep.Subtask.DBVersion.Sensitive,
			Issue:     imagesecModel.SensitiveCacheData,
		}

		if prep.Subtask.SensitiveCache.In(ly.Digest) {
			res.InCache = true
			result = append(result, res)
			continue
		}
		res.Scanned = true
		s2, k2, err := s.scanTarLayer(ctx, ly, prep.Subtask.SensitiveRules)
		if err != nil {
			res.Errors = append(res.Errors, err)
			s.Log.Err(err).Interface("layer", ly).Msg("ScanSensitive")
			result = append(result, res)
			continue
		}

		res.Sensitive = append(res.Sensitive, s2...)
		res.SaveFileToKafka = append(res.SaveFileToKafka, k2...)
		result = append(result, res)
	}
	return result
}

func (s *ScanSensitive) ScanLocalFile(ctx context.Context, pre *imagesecTypes.PrepareScan) imagesecTypes.ScanJobResult {
	result := imagesecTypes.ScanJobResult{}

	for i := range pre.Layers {
		ly := pre.Layers[i]
		s2, err := s.scanLocalLayer(ctx, ly, pre.Subtask.SensitiveRules)
		if err != nil {
			result.Errors = append(result.Errors, err)
			s.Log.Err(err).Interface("layer", ly).Msg("ScanSensitive")
			continue
		}
		result.Sensitive = append(result.Sensitive, s2...)
	}
	return result
}

func (s *ScanSensitive) ImageScan(ctx context.Context, pre *imagesecTypes.PrepareScan) []imagesecTypes.ScanJobResult {
	start := time.Now().Unix()
	s.logScanStart(pre)
	defer s.logScanEnd(start, pre)
	// if pre.Subtask.DeepScan {
	// 	return s.ScanLocalFile(ctx, pre)
	// }

	// 在开启动深度扫描时为啥不用文件扫描呢：
	// 因为有 WhiteOut 的机制存在，会导致两种方式扫描的结果可能不一致
	// 用文件扫描是正确的，用tar包是错的，因为还没有处理 whiteOut
	return s.ScanTarFile(ctx, pre)
}

func (s *ScanSensitive) scanTarLayer(ctx context.Context, ly *imagesecTypes.ImageLayer, rules []string) (
	[]imagesecTypes.SensitiveFile, []imagesecTypes.SaveFileToKafka, error) {
	sess := make([]imagesecTypes.SensitiveFile, 0)
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
			return sess, kaf, err
		}
		fi := header.FileInfo()

		if !scannerUtils.CommonFilter(fi) {
			continue
		}
		// 敏感文件不和规则关联，可以这样做
		if !s.filenameRule(ctx, header.Name, rules) && !s.checkPassword(ctx, header.Name, tarReader) {
			continue
		}

		fileByte, err := io.ReadAll(tarReader)
		if err != nil {
			s.Log.Err(err).Str("filename", header.Name).Msg("ReadAll")
			continue
		}
		sess = append(sess, imagesecTypes.SensitiveFile{
			Filename: header.Name,
			Layer:    ly.Digest,
			MD5:      scannerUtils.GetContentMd5(fileByte),
		})

		kaf = append(kaf, imagesecTypes.SaveFileToKafka{
			Layer:    ly.Digest,
			FileMd5:  scannerUtils.GetContentMd5(fileByte),
			Data:     fileByte,
			Filename: header.Name,
		})
	}
	return sess, kaf, nil
}

func (s *ScanSensitive) scanLocalLayer(ctx context.Context, ly *imagesecTypes.ImageLayer, rules []string) ([]imagesecTypes.SensitiveFile, error) {
	res := make([]imagesecTypes.SensitiveFile, 0)

	err := filepath.Walk(ly.LayerFilePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !scannerUtils.CommonFilter(info) {
			return nil
		}

		fd, err := os.Open(path)
		if err != nil {
			s.Log.Err(err).Str("file", path).Msg("ScanSensitive")
			return nil
		}
		defer func() { _ = fd.Close() }()

		fileByte, err := io.ReadAll(fd)
		if err != nil {
			s.Log.Err(err).Str("file", path).Msg("ScanSensitive")
			return nil
		}

		reader := bytes.NewReader(fileByte)

		// 敏感文件不和规则关联，可以这样做
		cn := ly.ContainerFilename(path)

		if !s.filenameRule(ctx, cn, rules) && !s.checkPassword(ctx, cn, reader) {
			return nil
		}

		ses := imagesecTypes.SensitiveFile{
			Filename: path,
			Layer:    ly.Digest,
			MD5:      scannerUtils.GetContentMd5(fileByte),
		}
		res = append(res, ses)

		// 不用读取需要上传的文件，后续统一读取要上传的文件
		return nil
	})
	return res, err
}

// 当前逻辑，只是检测出敏感文件就行，不和规则关联
func (s *ScanSensitive) filenameRule(ctx context.Context, fi string, rules []string) bool {
	// 默认
	for ru, rex := range s.Rule {
		if !rex.Enable || rex.RuleType != imagesecModel.SensitiveRuleTypeFilename {
			continue
		}
		com, ok := s.RegexpMap[ru]
		if !ok || com == nil {
			continue
		}

		if com.FindString(fi) != "" {
			return true
		}
	}

	// 自定义
	for _, ru := range rules {
		rex, err := regexp.Compile(ru)
		if err != nil {
			continue
		}
		if rex.FindString(fi) != "" {
			return true
		}
	}

	return false
}

func (s *ScanSensitive) checkPassword(ctx context.Context, filename string, reader io.Reader) bool {
	passwordFileExt := []string{".conf", ".yml", ".ini", ".env", ".properties", ".cfg", ".toml"}
	if !util.ExistInStringSlice(passwordFileExt, filepath.Ext(filename)) {
		return false
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if HasWeakPassword(line) {
			return true
		}
	}
	return false
}

func (s *ScanSensitive) SetDefaultRule() error {
	preData, err := scannerUtils.GetSensitiveRuleFromFile(consts.DefaultSensitiveRuleENPath)
	if err != nil {
		s.Log.Err(err).Msg("SetDefaultRule")
		return err
	}

	for i := range preData {
		data := &imagesecModel.SensitiveRule{
			Description: preData[i].Description,
			Value:       preData[i].Value,
			RuleType:    preData[i].SecretType,
			IsDefault:   true,
			Enable:      true,
		}
		s.Rule[data.Value] = data
		com, err := regexp.Compile(data.Value)
		if err != nil {
			continue
		}
		s.RegexpMap[data.Value] = com
	}

	return nil
}

func HasWeakPassword(line string) bool {
	pssStr := []string{"password", "passwd", "PASSWORD", "PASSWD"}
	for _, pas := range pssStr {
		if !strings.HasPrefix(line, pas) {
			continue
		}
		pss := strings.Replace(line, pas, "", 1)
		pss = strings.TrimSpace(pss)
		if strings.HasPrefix(pss, "=") {
			pss = strings.Replace(pss, "=", "", 1)
			pss = strings.TrimSpace(pss)
		}
		if strings.HasPrefix(pss, ":") {
			pss = strings.Replace(pss, ":", "", 1)
			pss = strings.TrimSpace(pss)
		}
		pattern := `^[a-zA-Z0-9]+$`
		match, _ := regexp.MatchString(pattern, pss)
		if match {
			return true
		}
	}
	return false
}

func (s *ScanSensitive) logScanEnd(start int64, pre *imagesecTypes.PrepareScan) {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).
		Int64("cost", time.Now().Unix()-start).Msg("scan job end")
}

func (s *ScanSensitive) logScanStart(pre *imagesecTypes.PrepareScan) {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Msg("scan job start")
}

package modify

import (
	"context"
	"path/filepath"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

// 对扫描结果做一些适配

type ResultModify struct {
	Log *scannerUtils.LogEvent
}

func (s *ResultModify) ConvertScanStatus(ctx context.Context, result *imagesecTypes.ReportScanResult) error {

	if len(result.Errors) > 0 {
		msg := make([]string, 0)
		for i := range result.Errors {
			msg = append(msg, result.Errors[i].Error())
		}
		result.StatusStr = imagesecModel.TaskStatusFailedStr
		result.Msg = strings.Join(msg, ",")
		// 扫描失败不会保存数据，所以直接不发送
		result.Webshell.HmWebshells = nil
		result.Sensitives.SensitiveFiles = nil
		result.OriginArtifact = nil
		result.Malware.AviraScanResults = nil
		result.Malware.ClamAvScanResults = nil
		result.SensitiveCache = nil
		result.LicenseCache = nil
		result.WebshellCache = nil
		result.MalwareCache = nil
	}

	return nil
}

// 扫描过程中会用到临时目录等，统一转换成镜像内的目录
func (s *ResultModify) ConvertToContainerPath(ctx context.Context, pre *imagesecTypes.PrepareScan, result *imagesecTypes.ReportScanResult) error {
	if pre == nil {
		return nil
	}
	for i := range result.Sensitives.SensitiveFiles {
		ses := result.Sensitives.SensitiveFiles[i]
		result.Sensitives.SensitiveFiles[i].Filename = s.containerFilename(ses.Filename, pre.Layers[ses.Layer])
	}

	for i := range result.Webshell.HmWebshells {
		ses := result.Webshell.HmWebshells[i]
		result.Webshell.HmWebshells[i].Filename = s.containerFilename(ses.Filename, pre.Layers[ses.Layer])
	}

	for i := range result.Malware.AviraScanResults {
		ses := result.Malware.AviraScanResults[i]
		result.Malware.AviraScanResults[i].Filename = s.containerFilename(ses.Filename, pre.Layers[ses.Layer])
	}
	for i := range result.Malware.ClamAvScanResults {
		ses := result.Malware.ClamAvScanResults[i]
		result.Malware.ClamAvScanResults[i].Filename = s.containerFilename(ses.Filename, pre.Layers[ses.Layer])
	}
	for i := range result.License {
		ses := result.License[i]
		result.License[i].Filename = s.containerFilename(ses.Filename, pre.Layers[ses.Layer])
	}
	return nil
}

func (s *ResultModify) ConvertToHostPath(ctx context.Context, pre *imagesecTypes.PrepareScan, result *imagesecTypes.ReportScanResult) error {
	if pre == nil {
		return nil
	}
	for i := range result.Sensitives.SensitiveFiles {
		ses := result.Sensitives.SensitiveFiles[i]
		result.Sensitives.SensitiveFiles[i].Filename = s.hostFilename(ses.Filename, pre.Layers[ses.Layer])
	}

	for i := range result.Webshell.HmWebshells {
		ses := result.Webshell.HmWebshells[i]
		result.Webshell.HmWebshells[i].Filename = s.hostFilename(ses.Filename, pre.Layers[ses.Layer])
	}

	for i := range result.Malware.AviraScanResults {
		ses := result.Malware.AviraScanResults[i]
		result.Malware.AviraScanResults[i].Filename = s.hostFilename(ses.Filename, pre.Layers[ses.Layer])
	}
	for i := range result.Malware.ClamAvScanResults {
		ses := result.Malware.ClamAvScanResults[i]
		result.Malware.ClamAvScanResults[i].Filename = s.hostFilename(ses.Filename, pre.Layers[ses.Layer])
	}
	for i := range result.License {
		ses := result.License[i]
		result.License[i].Filename = s.hostFilename(ses.Filename, pre.Layers[ses.Layer])
	}
	return nil
}

func (s *ResultModify) containerFilename(fi string, ly *imagesecTypes.ImageLayer) string {
	// 对于仓库镜像且不开启动深度扫描的话，可能不会解压文件
	if ly == nil {
		return fi
	}
	if ly.PreFix != "" {
		fi = strings.TrimPrefix(fi, ly.PreFix)
	}
	if !strings.HasPrefix(fi, "/") {
		return "/" + fi
	}
	return fi
}

func (s *ResultModify) hostFilename(fi string, ly *imagesecTypes.ImageLayer) string {
	if ly == nil {
		return fi
	}
	if strings.HasPrefix(fi, ly.PreFix) {
		return fi
	}

	nf := filepath.Join(ly.PreFix, fi)
	return nf
}

var modSinge *ResultModify

func NewResultModify() *ResultModify {
	if modSinge != nil {
		return modSinge
	}
	modSinge = &ResultModify{
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ResultModify"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		)}
	return modSinge
}

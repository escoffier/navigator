package types

import (
	"github.com/docker/distribution/manifest/schema2"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageLayer struct {
	Digest          string
	OriginalTarFile string // 文件服务器的tar
	TarFile         string //
	UnzipPath       string //
}

type PrepareScan struct {
	Layers        []ImageLayer
	ImageRootDir  string // 扫描完成后删除该
	Image         imagesec.Image
	UserDockerCli bool
	LayerFile     map[string][]string // 各层及的文件
	Errs          []error
}

type ManifestV2AndV1 struct {
	V2 *schema2.DeserializedManifest
	V1 *model.ManifestV1
}

func (v ManifestV2AndV1) GenLayerDigest() []string {
	res := make([]string, 0)
	if v.V2 != nil {
		for i := range v.V2.Layers {
			res = append(res, v.V2.Layers[i].Digest.String())
		}
		return res
	}
	if v.V1 != nil {
		for i := range v.V1.HistoryV1 {
			vv := v.V1.HistoryV1[i]
			if !vv.Throwaway {
				res = append(res, "sha256:"+vv.LayerDigest)
			}
		}
		return res
	}
	return res
}

type ScanSensitiveParam struct {
	Image          imagesec.Image
	UseDockerPull  bool         // 是否使用了 docker pull 来拉取镜像信息
	LayersFilePath []ImageLayer // 各层的路径信息
	Rules          []imagesec.SensitiveRule
}

type MalwareScanParam struct {
	Image          imagesec.Image
	UseDockerPull  bool         // 是否使用了 docker pull 来拉取镜像信息
	LayersFilePath []ImageLayer // 各层的路径信息
}

type WebshellScanRes struct {
	Webshell []imagesec.Webshell
	Issue    []imagesec.WebshellToImage
}

type ScanVulnResult struct {
}

type ScanVulnParam struct {
	CacheURL     string
	Image        imagesec.Image
	UseDockerCli bool
}

type ImageScanCorrelateData struct {
	Image          imagesec.Image
	Sensitive      []imagesec.SensitiveFile
	SensitiveIssue []imagesec.SensitiveToImage
	Webshell       []imagesec.Webshell
	WebshellIssue  []imagesec.WebshellToImage
	Vuln           []imagesec.Vuln
	VulnIssue      []imagesec.VulnToImage
	Pkg            []imagesec.Pkg
	PkgIssue       []imagesec.PkgToImage
	Malware        []imagesec.Malware
	MalwareIssue   []imagesec.MalwareToImage
	WebFrame       []model.WebFrameInfo
}

package types

import (
	"context"

	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type SensitiveScanner interface {
	ScanFilename(ctx context.Context, filename string, rules []imagesecModel.SensitiveRule) (imagesecTypes.SensitiveFileResults, error)
	ScanFileContent(ctx context.Context, filename string, rules []imagesecModel.SensitiveRule) (imagesecTypes.SensitiveFileResults, error)
}

type VulnScanner interface {
	ScanVuln(ctx context.Context, imageName string) (*report.Report, error)
}

type MalwareScanner interface {
	ScanMalware(ctx context.Context, layer ImageLayer, recursion bool) ([]imagesecModel.Malware, error)
}

type WebFrameScanner interface {
	FindWebFrame(ctx context.Context, layer ImageLayer) ([]model.WebFrameInfo, error)
}

type WebshellScanner interface {
	ScanWebshell(ctx context.Context, layer ImageLayer, recursion bool) ([]imagesecModel.Webshell, error)
}

type Config struct {
	CacheServerURL string // image cache server url
	RepoName       string // image name,eg: library/nginx
	Tag            string // tag,eg: latest
	URL            string // registry url
	Username       string
	Password       string
}

type LibImageScanner interface {
	Scan(ctx context.Context, task imagesecTypes.ScanSubTask) (imagesecTypes.ScanResult, error)
	Send(ctx context.Context, res imagesecTypes.ScanResult) error
}

package sensitive

import (
	"context"
	"fmt"
	"regexp"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type SensitiveScanner struct {
	RegexpMap map[string]*regexp.Regexp
	Rule      map[string]*imagesecModel.SensitiveRule
}

func (s SensitiveScanner) ScanFilename(ctx context.Context, filename string, rules []imagesecModel.SensitiveRule) (
	imagesecTypes.SensitiveFileResults, error) {
	return imagesecTypes.SensitiveFileResults{}, nil
}

func (s SensitiveScanner) ScanFileContent(ctx context.Context, filename string, rules []imagesecModel.SensitiveRule) (imagesecTypes.SensitiveFileResults, error) {
	return imagesecTypes.SensitiveFileResults{}, fmt.Errorf("not implement")
}

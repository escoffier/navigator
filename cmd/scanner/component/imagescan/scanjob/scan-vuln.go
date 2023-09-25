package scanjob

import (
	"context"
	"errors"

	"github.com/google/go-containerregistry/pkg/name"
	"scm.tensorsecurity.cn/tensorsecurity-rd/trivy/pkg/report"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
)

type ExecutorScanVuln struct {
	imageCacheURL string
}

func (e *ExecutorScanVuln) Scan(ctx context.Context, param Param) (*report.Report, error) {
	// get image cache url
	u, ok := param["imageCacheUrl"].(string)
	if !ok {
		logging.Get().Error().Msg("miss 'imageCacheUrl' in parameter")
		return nil, errors.New("miss 'imageCacheUrl' in parameter")
	}
	e.imageCacheURL = u
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)
	ref, err := name.ParseReference(e.imageCacheURL, nameOpts...)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("parse image failed")
		return nil, errors.New("parse image failed")
	}

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()
	newImage := "0.0.0.0:5566/" + repositoryName + ":" + tag
	dockerFlag, ok := param["docker"].(int)
	if ok && dockerFlag == 1 {
		Image, ok := param["dockerImage"].(string)
		if ok {
			newImage = Image
		}
	}
	// scan
	if component.TrivyService == nil {
		logging.Get().Error().Msg("TrivyService didn't start")
		return nil, errors.New("TrivyService didn't start")
	}

	result, err := component.TrivyService.Scan(ctx, newImage)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("Scan image failed")
		return nil, errors.New("scan image failed")
	}
	return result, nil
}

func NewScanVuln() *ExecutorScanVuln {
	e := &ExecutorScanVuln{}
	return e
}

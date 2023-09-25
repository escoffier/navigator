package scanjob

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

func (s *RegistryImageScan) PrepareScan(ctx context.Context, ta imagesecTypes.ScanSubTask) (*types.PrepareScan, error) {

	res := &types.PrepareScan{
		Layers:        make([]types.ImageLayer, 0),
		ImageRootDir:  filepath.Join(s.ScanP.RootPath, fmt.Sprintf("%d", ta.RegImageMeta.UniqueID)),
		Image:         imagesecModel.Image{},
		UserDockerCli: false,
		LayerFile:     make(map[string][]string),
		Errs:          make([]error, 0),
	}
	if err := s.ScanP.PullImage(ctx, ta, res); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("image", ta.RegImageMeta).Msg("PrepareScan")
		return nil, err
	}
	if err := s.ScanP.PrepareFile(ctx, ta, res); err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Interface("image", ta.RegImageMeta).Msg("PrepareScan")
		return nil, err
	}

	for i := range res.Errs {
		logging.Get().Err(res.Errs[i]).Str("module", "imagescan").Interface("image", ta.RegImageMeta).Msg("PrepareScan")
	}

	logging.Get().Debug().Str("module", "imagescan").Interface("scanP", res).Interface("image", ta.RegImageMeta).
		Msg("PrepareScan")

	return res, nil
}

func (s *RegistryImageScan) ScanVuln(ctx context.Context, ta imagesecTypes.ScanSubTask) error {
	im, err := s.changCacheUrl(ta.RegImageMeta.ImageName())
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("imageName", ta.RegImageMeta.ImageName()).Msg("changCacheUrl")
		return err
	}

	vuln, err := s.TrivyEngin.ScanVuln(ctx, im)

	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("imageName", im).Msg("ScanVuln")
		return err
	}
	logging.Get().Info().Str("module", "imagescan").Interface("vuln", vuln).Msg("ScanVuln")
	return nil
}

func (s *RegistryImageScan) ScanAvira(ctx context.Context, res *types.PrepareScan) error {
	for _, files := range res.LayerFile {
		for i := range files {
			fi := files[i]
			file, err := s.AviraEngin.ScanFile(ctx, fi)
			if err != nil {
				logging.Get().Err(err).Str("module", "imagescan").Msg("ScanAvira")
				continue
			}
			if len(file) > 0 {
				logging.Get().Info().Str("module", "imagescan").Interface("avira", file).Msg("ScanAvira")
			}
		}
	}

	logging.Get().Info().Str("module", "imagescan").Msg("ScanAvira end")
	return nil
}

func (s *RegistryImageScan) ScanWebshell(ctx context.Context, res *types.PrepareScan) error {

	for i := range res.Layers {
		pa := res.Layers[i].UnzipPath
		ws, err := s.HM.ScanWebshell(ctx, pa)
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("ScanWebshell")
			continue
		}
		logging.Get().Info().Str("module", "imagescan").Str("path", pa).
			Interface("webshell", ws).Msg("ScanWebshell")
	}

	return nil
}

func (s *RegistryImageScan) changCacheUrl(im string) (string, error) {
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)
	ref, err := name.ParseReference(im, nameOpts...)
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("parse image failed")
		return "", err
	}

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()
	newImage := s.ImageCacheURL + repositoryName + ":" + tag
	return newImage, nil
}

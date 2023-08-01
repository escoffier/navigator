package scanjob

import (
	"context"

	"github.com/pkg/errors"

	"gitlab.com/security-rd/go-pkg/logging"

	imageCache "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/image-cache"
)

type ExecutorDeleteLayer struct {
}

func (s *ExecutorDeleteLayer) Run(ctx context.Context, param Param) error {
	layers, ok := param["layers"].([]string)
	if !ok {
		logging.Get().Error().Msg("miss 'layersFilePath' in parameter")
		return errors.New("miss 'layersFilePath' in parameter")
	}
	client1, err := imageCache.NewLocalLayerManageClientT("/layer")
	if err != nil {
		return err
	}
	for k := range layers {
		if err := client1.DeleteLayer(layers[k]); err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msgf("delete layer %v Failed", layers[k])
			continue
		}
	}
	return nil
}

func NewDeleteLayer() *ExecutorDeleteLayer {
	return &ExecutorDeleteLayer{}
}

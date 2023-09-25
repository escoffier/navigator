package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func (s *RegSyncSrv) createImageExtender(ctx context.Context, image warehouse.Image) (*warehouse.ListImagesRes, error) {
	layers := GetLayers(image)
	configFile := GetConfigFile(image)
	report := &imagesecTypes.NodeReport{
		UUID:       util.GenerateUUIDHex(),
		LibImages:  make([]imagesecTypes.ImageMeta, 0),
		ReportedAt: time.Now().UnixMilli(),
		RegInfo:    imagesecTypes.RegInfo{RegID: image.RegistryID, Url: image.RegistryUrl},
	}

	imageMeta := &imagesecTypes.ImageMeta{
		Digests:   []string{image.ImageDigest},
		RepoTags:  []string{fmt.Sprintf("%s/%s:%s", image.RegistryUrl, image.Repository, image.Tag)},
		Os:        configFile.OS,
		Size:      int64(image.Size),
		Layers:    layers,
		ENVS:      GetEnvs(configFile),
		User:      configFile.Config.User,
		Created:   image.Created.String(),
		PullCount: image.PullCount,
	}

	if image.Created.IsZero() {
		imageMeta.Created = configFile.Created.String()
	}
	logging.Get().Debug().Str("module", "RegistryImage").Interface("imageMeta", imageMeta).Msg("get a imageMeta")

	report.LibImages = append(report.LibImages, *imageMeta)

	bys, err := json.Marshal(report)
	if err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("Marshal")
		return nil, err
	}

	msg := kafka.Message{
		Topic: model.NodeImageTopic,
		Key:   []byte(model.NodeImageKey),
		Value: bys,
	}

	if err := s.MqWriter.Write(ctx, msg.Topic, msg); err != nil {
		logging.Get().Err(err).Str("module", "RegistryImage").Msg("SyncAllImage SendToMq")
		return nil, err
	}
	logging.Get().Debug().Str("module", "RegistryImage").Msg("sync a image and send to kafka")

	return &warehouse.ListImagesRes{}, nil
}

func (s *RegSyncSrv) updateImageLastSyncExtender(ctx context.Context, image warehouse.Image) error {
	return nil
}

func (s *RegSyncSrv) createOrAddRetryCountExtender(ctx context.Context, image warehouse.Image) error {
	return nil
}

func (s *RegSyncSrv) deleteImageRetryExtender(ctx context.Context, image warehouse.Image) error {
	return nil
}

func (s *RegSyncSrv) getExtender() warehouse.Extender {
	return warehouse.Extender{
		CreateImageExtender:           s.createImageExtender,
		CreateOrAddRetryCountExtender: s.createOrAddRetryCountExtender,
		DeleteImageRetryExtender:      s.deleteImageRetryExtender,
		UpdateImageLastSyncExtender:   s.updateImageLastSyncExtender,
	}
}

func GetLayers(image warehouse.Image) []imagesecTypes.Layer {
	// fixme(liuqianli) 没有对ManifestV2做兼容
	manifestV2 := model.ManifestV2{}
	if image.ManifestV2 != "" {
		_ = json.Unmarshal([]byte(image.ManifestV2), &manifestV2)
	}
	config := model.ConfigFile{}
	if image.ConfigJSON != "" {
		_ = json.Unmarshal([]byte(image.ConfigJSON), &config)
	}
	logging.Get().Debug().Str("module", "RegistryImage").Interface("configFile", config).Msg("GetLayers")
	logging.Get().Debug().Str("module", "RegistryImage").Interface("manifestV2", manifestV2).Msg("GetLayers")

	layers1 := make([]imagesecTypes.Layer, 0)
	for i := range manifestV2.Layers {
		ly := manifestV2.Layers[i]
		nl := imagesecTypes.Layer{
			Size:   ly.Size,
			Digest: ly.Digest,
		}
		layers1 = append(layers1, nl)
	}

	history := config.History
	layers2 := make([]imagesecTypes.Layer, 0)
	for i := range history {
		if history[i].EmptyLayer {
			continue
		}
		ly := history[i]
		nl := imagesecTypes.Layer{
			Comment:   ly.Comment,
			Created:   ly.Created.UnixMilli(),
			CreatedBy: ly.CreatedBy,
		}
		layers2 = append(layers2, nl)
	}
	layers := make([]imagesecTypes.Layer, 0)
	min := util.MinInt(len(layers1), len(layers2))
	for i := 0; i < min; i++ {
		nl := imagesecTypes.Layer{
			Comment:   layers2[i].Comment,
			Created:   layers2[i].Created,
			CreatedBy: layers2[i].CreatedBy,
			Size:      layers1[i].Size,
			Digest:    layers1[i].Digest,
		}
		layers = append(layers, nl)
	}
	return layers
}

func GetConfigFile(image warehouse.Image) model.ConfigFile {
	configFile := model.ConfigFile{}
	if len(image.ConfigJSON) > 0 {
		_ = json.Unmarshal([]byte(image.ConfigJSON), &configFile)
	}
	return configFile
}

func GetEnvs(configFile model.ConfigFile) []string {
	envs := make([]string, 0)
	for _, env := range configFile.Config.Env {
		envs = append(envs, env)
	}
	return envs
}

package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/segmentio/kafka-go"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecType "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 持续监控低版本的镜像同步
func (s *RegSyncSrv) SyncImageMeta(ctx context.Context) error {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("Migrate SyncImageMeta")
			}
		}()

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			_ = s.DeleteImage(ctx)
			_ = s.syncImageMeta(ctx)
			ticker.Reset(time.Minute)
		}
	}()
	return nil
}

func (s *RegSyncSrv) syncImageMeta(ctx context.Context) error {
	filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit)

	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	cnt := 0
	for {
		<-ticker.C
		registry, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
		if err != nil {
			s.Log.Err(err).Msg("MigrateImage")
			continue
		}
		if len(registry) == 0 {
			break
		}
		regs := make(map[int64]imagesecModel.Registry)
		retIds := make([]int64, 0)
		for i := range registry {
			retIds = append(retIds, registry[i].ID)
			regs[registry[i].ID] = registry[i]
		}

		images, _, err := s.PreImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{
			Where:    fmt.Sprintf("status = 0"),
			NotCount: true,
			RegIds:   retIds,
			Fields:   []string{"id", "status"},
		}, filter)

		if err != nil {
			s.Log.Err(err).Msg("SyncImageMeta failed")
			return err
		}
		if len(images) == 0 {
			break
		}
		for i := range images {
			if images[i].Status != 0 {
				continue
			}
			_ = s.MigrateImage2(ctx, images[i].ID)
		}
		s.Log.Info().Int("syncImageCnt", len(images)).Msg("Migrate SyncImageMeta")
	}

	s.Log.Info().Int("syncImageCnt", cnt).Msg("Migrate SyncImageMeta end")
	return nil
}

func (s *RegSyncSrv) MigrateImage2(ctx context.Context, imageID int64) error {
	registry, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
	if err != nil {
		s.Log.Err(err).Msg("MigrateImage")
		return err
	}
	if len(registry) == 0 {
		return nil
	}
	regs := make(map[int64]imagesecModel.Registry)
	for i := range registry {
		regs[registry[i].ID] = registry[i]
	}
	images, _, err := s.PreImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{InIds: []int64{imageID}}, nil)
	if err != nil {
		s.Log.Err(err).Msg("MigrateImage")
		return err
	}
	if len(images) == 0 {
		s.Log.Info().Int64("imageID", imageID).Msg("MigrateImage not find image")
		return err
	}
	im := images[0]

	reg, ok := regs[im.RegistryID]
	if !ok {
		return nil
	}

	im.Library = reg.Url

	nr := ToNodeReport(im)
	if err := s.sendImageToKafka(ctx, nr); err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("MigrateImage sendImageToKafka")
		return err
	}
	_ = s.updateImageAdapted(ctx, im.ID)

	s.Log.Info().Int64("imageID", imageID).Str("imageName", im.GetImageName()).Msg("MigrateImage success")
	return nil
}

// 仓库删除之后，删除镜像
func (s *RegSyncSrv) DeleteImage(ctx context.Context) error {
	filter := imagesecModel.EmptyFilter().SetLimit(consts.DefaultMaxLimit)

	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	cnt := 0
	for {
		<-ticker.C
		registry, _, err := s.registryDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.TrueString})
		if err != nil {
			s.Log.Err(err).Msg("MigrateImage")
			continue
		}
		if len(registry) == 0 {
			break
		}
		retIds := make([]int64, 0)
		for i := range registry {
			retIds = append(retIds, registry[i].ID)
		}

		images, _, err := s.PreImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{
			NotCount: true,
			RegIds:   retIds,
			Fields:   []string{"id"},
		}, filter)

		if err != nil {
			s.Log.Err(err).Msg("SyncImageMeta failed")
			return err
		}
		if len(images) == 0 {
			break
		}
		for i := range images {
			_ = s.PreImageDal.DeleteImage(ctx, images[i].ID)
		}
		s.Log.Info().Int("syncImageCnt", len(images)).Msg("Migrate registry deleted ,delete image")
	}

	s.Log.Info().Int("syncImageCnt", cnt).Msg("Migrate SyncImageMeta end")
	return nil
}

func (s *RegSyncSrv) updateImageAdapted(ctx context.Context, imageID int64) error {
	updater := map[string]interface{}{
		"status": consts.ImageStatusImageAdapted,
	}
	err := s.PreImageDal.UpdateImage(ctx, fmt.Sprintf("id = %d", imageID), updater, nil)
	if err != nil {
		s.Log.Err(err).Msg("updateImageAdapted")
		return err
	}
	return nil
}

func (s *RegSyncSrv) sendImageToKafka(ctx context.Context, report imagesecType.NodeReport) error {

	bys, err := json.Marshal(report)
	if err != nil {
		s.Log.Err(err).Msg("Marshal")
		return err
	}
	msg := kafka.Message{
		Topic: consts.NodeImageTopic,
		Key:   []byte(consts.NodeImageKey),
		Value: bys,
	}

	if err := s.MqWriter.Write(ctx, msg.Topic, msg); err != nil {
		s.Log.Err(err).Msg("SyncAllImage SendToMq")
		return err
	}
	s.Log.Info().Msg("send kafka image end")
	return nil
}

func ToNodeReport(image model.ImageList) imagesecType.NodeReport {

	nr := imagesecType.NodeReport{
		RegImages:       make([]imagesecType.ImageMeta, 0),
		RegInfo:         imagesecType.RegInfo{RegID: image.RegistryID},
		ReportedAt:      time.Now().UnixMilli(),
		ReportDBVersion: imagesecType.ReportDBVersion{},
	}

	layers := getLayers(image)
	im := imagesecType.ImageMeta{
		Created:  image.FirstPushTime.String(),
		Digests:  []string{image.Digest},
		RepoTags: []string{fmt.Sprintf("%s/%s:%s", image.Library, image.FullRepoName, image.Tags)},
		Os:       image.OS,
		Size:     int64(image.Size),
		Layers:   layers,
		ENVS:     make([]string, 0),
		User:     image.GetBootUser(),
	}
	if image.ConfigFile != nil {
		im.ENVS = image.ConfigFile.Config.Env
	}
	nr.RegImages = append(nr.RegImages, im)

	return nr
}

func getLayers(image model.ImageList) []imagesecType.Layer {

	layers := make([]imagesecType.Layer, 0)
	if image.ManifestV2 == nil || image.ConfigFile == nil {
		return layers
	}

	manifestV2 := image.ManifestV2

	layers1 := make([]imagesecType.Layer, 0)
	for i := range manifestV2.Layers {
		ly := manifestV2.Layers[i]
		nl := imagesecType.Layer{
			Size:   ly.Size,
			Digest: ly.Digest,
		}
		layers1 = append(layers1, nl)
	}

	history := image.ConfigFile.History
	layers2 := make([]imagesecType.Layer, 0)
	for i := range history {
		if history[i].EmptyLayer {
			continue
		}
		ly := history[i]
		nl := imagesecType.Layer{
			Comment:   ly.Comment,
			Created:   ly.Created.UnixMilli(),
			CreatedBy: ly.CreatedBy,
		}
		layers2 = append(layers2, nl)
	}
	minInt := util.MinInt(len(layers1), len(layers2))
	for i := 0; i < minInt; i++ {
		nl := imagesecType.Layer{
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

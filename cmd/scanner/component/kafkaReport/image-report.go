package imagesecReport

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	imageMetaSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta/metaGlobal"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageReport struct {
	imageDal      imagesecStore.ImageMetaDal
	nodeReportDal imagesecStore.NodeInfoDal
	scanResultDal imagesecStore.ScanResultDal
	mqReader      mq.Reader
	configDal     imagesecStore.ScanImageConfigDal
	scanTaskSrv   service.ScanTaskService
	NodeImageQ    *ImageQueue
	RegImageQ     *ImageQueue
}

var imageReport *ImageReport

func NewImageReport(
	imageDal imagesecStore.ImageMetaDal,
	nodeInfoDal imagesecStore.NodeInfoDal,
	scanResultDal imagesecStore.ScanResultDal,
	mqReader mq.Reader,
	configDal imagesecStore.ScanImageConfigDal,
	scanTaskSrv service.ScanTaskService,
) *ImageReport {
	if imageReport != nil {
		return imageReport
	}
	s := &ImageReport{
		imageDal:      imageDal,
		nodeReportDal: nodeInfoDal,
		scanResultDal: scanResultDal,
		mqReader:      mqReader,
		configDal:     configDal,
		scanTaskSrv:   scanTaskSrv,
		NodeImageQ:    NewImageQueue(consts.SyncScanTaskCheckInterval),
		RegImageQ:     NewImageQueue(consts.SyncScanTaskCheckInterval),
	}
	s.AddScanTask(context.Background())
	imageReport = s
	return imageReport
}

func (s *ImageReport) ReceiveReport(ctx context.Context) error {

	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "KafkaReport").Msg("ImageReport scanner in slave cluster,ignore handle kafka msg")
		return nil
	}

	logging.Get().Info().Str("module", "KafkaReport").Msg("ImageReport scanner in main cluster,ready to handle kafka msg")

	ch := make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Stack().Msg("ImageReport")
			}
		}()

		if err := s.handleMsg(ch); err != nil {
			logging.Get().Err(err).Str("module", "KafkaReport").Msg("ImageReport finished")
		}
	}()

	logging.Get().Info().Str("module", "KafkaReport").Msg("ImageReport receive kafka started end")

	return nil
}

func (s *ImageReport) ReceiveAssetReport(ctx context.Context, msg kafka.Message) error {

	var report imagesecTypes.NodeReport
	err := json.Unmarshal(msg.Value, &report)

	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("failed to unmarshal node image msg")
		return err
	}

	logging.Get().Debug().Str("module", "KafkaReport").
		Str("uuid", report.UUID).
		Str("clusterKey", report.NodeInfo.ClusterKey).
		Str("node", report.NodeInfo.HostName).
		Str("reg", report.RegInfo.Url+report.RegInfo.Name).
		Int64("reportedAt", report.ReportedAt).
		Interface("images", report).
		Msg("receive image report")

	_ = s.NodeImage(ctx, report)
	_ = s.RegImage(ctx, report)
	return nil
}

func (s *ImageReport) NodeImage(ctx context.Context, imageReport imagesecTypes.NodeReport) error {
	if len(imageReport.NodeImages) == 0 {
		return nil
	}
	images, node, envs := GetNodeImageInfo(imageReport)
	if err := node.Check(); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("node info incorrect")
		return err
	}

	logging.Get().Debug().Str("module", "KafkaReport").Int("images", len(images)).Int("envs", len(envs)).Msg("ImageReport ImageMateToModel")

	if err := s.nodeReportDal.CreateNodeInfo(ctx, node); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Interface("node", node).Msg("ImageReport CreateNodeInfo")
	}

	for imageID, en := range envs {
		if err := s.scanResultDal.CreateImageEnv(ctx, imageID, en); err != nil {
			logging.Get().Err(err).Str("module", "KafkaReport").Uint64("imageID", images[0].UniqueID).Msg("ImageReport CreateImageEnv")
		}
	}

	if len(images) == 0 {
		return nil
	}

	uniqueIds := make([]uint64, 0)
	for i := range images {
		uniqueIds = append(uniqueIds, images[i].GenUniqueID())
	}
	pre, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{UniqueIds: uniqueIds})
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("configType", imagesecModel.ImageFromNode).Msg("ImageReport SearchImage")
		return err
	}
	exit := make(map[uint64]bool)
	for i := range pre {
		exit[pre[i].UniqueID] = true
	}

	addImage := make([]*imagesecModel.Image, 0)
	nodeImageDigest := make([]string, 0)
	for i := range images {
		nodeImageDigest = append(nodeImageDigest, images[i].Digest)
		if _, ok := exit[images[i].UniqueID]; !ok {
			addImage = append(addImage, images[i])
		}
	}
	// 更新节点镜像是否在仓库镜像中,会有并发安全
	libImages, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{Digests: nodeImageDigest, Fields: []string{"digest"}})
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Interface("image", images).Msg("ImageReport SearchImage")
		return err
	}
	digestExit := make(map[string]bool)
	for i := range libImages {
		digestExit[libImages[i].Digest] = true
	}
	for i := range images {
		im := images[i]
		im.Flag = im.GenDefaultFlag()
		if digestExit[images[i].Digest] {
			images[i].Flag = util.SetBit1(util.SetBit0(im.Flag, imagesecModel.FlagImageNotInRegistry), imagesecModel.FlagImageInRegistry)
		}

		if !digestExit[images[i].Digest] {
			images[i].Flag = util.SetBit1(util.SetBit0(im.Flag, imagesecModel.FlagImageInRegistry), imagesecModel.FlagImageNotInRegistry)
		}
	}

	if err = s.imageDal.CreateNodeImage(ctx, images); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Interface("image", images).Msg("ImageReport CreateNodeImage")
		return err
	}

	_ = s.AddNodeImageScanTask(ctx, addImage)

	return nil
}

func (s *ImageReport) RegImage(ctx context.Context, imageReport imagesecTypes.NodeReport) error {
	images, envs := GetRegImageInfo(imageReport)

	logging.Get().Debug().Str("module", "KafkaReport").Int("images", len(images)).Int("envs", len(envs)).Msg("ImageReport ImageMateToModel")
	if len(images) == 0 {
		return nil
	}

	updateChan := imageMetaSrv.GetImageUpdateChan()
	for imageID, en := range envs {
		if err := s.scanResultDal.CreateImageEnv(ctx, imageID, en); err != nil {
			logging.Get().Err(err).Str("module", "KafkaReport").Uint64("imageID", images[0].UniqueID).Msg("ImageReport CreateImageEnv")
		}
	}

	uniqueIds := make([]uint64, 0)
	for i := range images {
		uniqueIds = append(uniqueIds, images[i].GenUniqueID())
	}
	pre, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{UniqueIds: uniqueIds})
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("configType", imagesecModel.ImageFromNode).Msg("ImageReport SearchImage")
		return err
	}
	exit := make(map[uint64]bool)
	for i := range pre {
		exit[pre[i].UniqueID] = true
	}

	addImage := make([]*imagesecModel.Image, 0)
	for i := range images {
		if _, ok := exit[images[i].UniqueID]; !ok {
			go func(im *imagesecModel.Image) { updateChan.AddRegImageChan <- im }(images[i])
			addImage = append(addImage, images[i])
		}
	}

	if err = s.imageDal.CreateRegImage(ctx, images); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Interface("image", images).Msg("ImageReport CreateRegImage")
		return err
	}

	_ = s.AddRegImageScanTask(ctx, addImage)

	return nil
}

func (s *ImageReport) AddNodeImageScanTask(ctx context.Context, newImages []*imagesecModel.Image) error {
	if len(newImages) == 0 {
		return nil
	}
	autoAdd := false
	config, err := s.configDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("ImageReport CreateScanTask")
	} else {
		autoAdd = config.ImageScanConfig.AutoScanAdded
	}
	if !autoAdd {
		logging.Get().Info().Str("module", "KafkaReport").Bool("autoAdd", autoAdd).Msg("CreateScanTask")
		return nil
	}
	for i := range newImages {
		s.NodeImageQ.Add(newImages[i])
	}

	return nil
}

func (s *ImageReport) AddRegImageScanTask(ctx context.Context, newImages []*imagesecModel.Image) error {
	if len(newImages) == 0 {
		return nil
	}

	autoAdd := false
	config, err := s.configDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeRegScanImage)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("configType", imagesecModel.ConfigTypeRegScanImage).Msg("ImageReport CreateScanTask")
	} else {
		autoAdd = config.ImageScanConfig.AutoScanAdded
	}
	if !autoAdd {
		logging.Get().Info().Str("module", "KafkaReport").Bool("autoAdd", autoAdd).Msg("ImageReport CreateScanTask")
		return nil
	}

	for i := range newImages {
		s.RegImageQ.Add(newImages[i])
	}

	return nil
}

func (s *ImageReport) handleMsg(stopCh <-chan struct{}) error {
	err := s.mqReader.Subscribe(model.NodeImageTopic, model.NodeImageGroup, s.ReceiveAssetReport)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("failed to sub message queue")
		return err
	}
	logging.Get().Info().Str("module", "KafkaReport").Msg("sub message queue ok")
	<-stopCh
	logging.Get().Info().Str("module", "KafkaReport").Msg("sub message queue end")

	return fmt.Errorf("quit message handler")
}

func (s *ImageReport) AddScanTask(ctx context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("module", "KafkaReport").Msg("AddScanTask")
			}
		}()

		ticker := time.NewTicker(time.Minute * 2)
		defer ticker.Stop()
		for {
			<-ticker.C
			if !s.RegImageQ.NeedCreateScanTask() {
				continue
			}
			ims := s.RegImageQ.GetImages()
			taskInfo := imagesecModel.ImageScanTask{
				ImageFromType: imagesecModel.ImageFromRegistry,
				ScanType:      imagesecModel.ImageSyncTrigger,
			}

			param := imagesecModel.ImageSearchApiParam{UniqueIds: ims, ImageFromType: imagesecModel.ImageFromRegistry}
			if err := s.scanTaskSrv.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				logging.Get().Err(err).Str("module", "KafkaReport").Interface("taskInfo", taskInfo).Msg("ImageReport CreateScanTask")
				continue
			}
			logging.Get().Info().Str("module", "KafkaReport").Interface("taskInfo", taskInfo).Msg("ImageReport CreateScanTask succeed")
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("module", "KafkaReport").Msg("AddScanTask")
			}
		}()

		ticker := time.NewTicker(time.Minute * 2)
		defer ticker.Stop()
		for {
			<-ticker.C
			if !s.NodeImageQ.NeedCreateScanTask() {
				continue
			}
			ims := s.NodeImageQ.GetImages()
			taskInfo := imagesecModel.ImageScanTask{
				ImageFromType: imagesecModel.ImageFromNode,
				ScanType:      imagesecModel.ImageSyncTrigger,
				Status:        imagesecModel.TaskStatusPending,
			}

			param := imagesecModel.ImageSearchApiParam{UniqueIds: ims, ImageFromType: imagesecModel.ImageFromNode}
			if err := s.scanTaskSrv.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				logging.Get().Err(err).Str("module", "KafkaReport").Interface("taskInfo", taskInfo).Msg("ImageReport CreateScanTask")
				continue
			}
			logging.Get().Info().Str("module", "KafkaReport").Interface("taskInfo", taskInfo).Msg("ImageReport CreateScanTask succeed")
		}
	}()
}

package nodereport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

// 上报节点信息
type ReceiveNodeReportService interface {
	ReceiveNodeReport(ctx context.Context) error
	AddDetectTask(ctx context.Context) error
}

type NodeImageReport struct {
	imageDal      imagesecStore.ImageMetaDal
	nodeReportDal imagesecStore.NodeInfoDal
	scanResultDal imagesecStore.ScanResultDal
	mqReader      mq.Reader
	configDal     imagesecStore.ScanImageConfigDal
	scanTaskSrv   imagescan.ScanTaskService
}

func NewNodeImageReport(
	imageDal imagesecStore.ImageMetaDal,
	nodeInfoDal imagesecStore.NodeInfoDal,
	scanResultDal imagesecStore.ScanResultDal,
	mqReader mq.Reader,
	configDal imagesecStore.ScanImageConfigDal,
	scanTaskSrv imagescan.ScanTaskService,
) *NodeImageReport {
	return &NodeImageReport{
		imageDal:      imageDal,
		nodeReportDal: nodeInfoDal,
		scanResultDal: scanResultDal,
		mqReader:      mqReader,
		configDal:     configDal,
		scanTaskSrv:   scanTaskSrv,
	}
}

func (s *NodeImageReport) AddDetectTask(ctx context.Context) error {
	return nil
}

func (s *NodeImageReport) ReceiveNodeReport(ctx context.Context) error {

	if os.Getenv("IS_MAIN_CLUSTER") != consts.TrueString {
		logging.Get().Info().Msg("NodeImageReport scanner in slave cluster,ignore handle kafka msg")
		return nil
	}

	logging.Get().Info().Msg("NodeImageReport scanner in main cluster,ready to handle kafka msg")

	ch := make(chan struct{})

	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Stack().Msg("NodeImageReport")
		}
		if err := s.handleMsg(ch); err != nil {
			logging.Get().Err(err).Msg("NodeImageReport finished")
		}
	}()

	logging.Get().Info().Msg("NodeImageReport receive kafka started end")

	return nil
}

func (s *NodeImageReport) ReceiveAssetReport(ctx context.Context, msg kafka.Message) error {

	var imageReport imagesecTypes.NodeReport
	err := json.Unmarshal(msg.Value, &imageReport)

	if err != nil {
		logging.Get().Err(err).Msg("failed to unmarshal node image msg")
		return err
	}

	logging.Get().Debug().
		Str("uuid", imageReport.UUID).
		Str("clusterKey", imageReport.NodeInfo.ClusterKey).
		Str("node", imageReport.NodeInfo.HostName).
		Int64("reportedAt", imageReport.ReportedAt).
		Interface("images", imageReport).
		Msg("receive node image report")

	images, node, envs := ImageMateToModel(imageReport)
	if err := node.Check(); err != nil {
		logging.Get().Err(err).Msg("node info incorrect")
		return err
	}

	logging.Get().Debug().Int("images", len(images)).Int("envs", len(envs)).Msg("NodeImageReport ImageMateToModel")

	if err = s.nodeReportDal.CreateNodeInfo(ctx, node); err != nil {
		logging.Get().Err(err).Interface("node", node).Msg("NodeImageReport CreateNodeInfo")
	}

	for imageID, en := range envs {
		if err = s.scanResultDal.CreateImageEnv(ctx, imageID, en); err != nil {
			logging.Get().Err(err).Uint64("imageID", images[0].UniqueID).Msg("NodeImageReport CreateImageEnv")
		}
	}

	if len(images) == 0 {
		return nil
	}

	uniqueIds := make([]uint64, 0)
	for i := range images {
		uniqueIds = append(uniqueIds, images[i].GenUniqueID())
	}
	pre, _, err := s.imageDal.SearchImage(ctx, imagesecModel.NodeImageDalParam{UniqueIds: uniqueIds})
	if err != nil {
		logging.Get().Err(err).Str("configType", imagesecModel.ImageFromNode).Msg("NodeImageReport SearchImage")
		return err
	}
	exit := make(map[uint64]bool)
	for i := range pre {
		exit[pre[i].UniqueID] = true
	}

	addImage := make([]*imagesecModel.Image, 0)

	for i := range images {
		if _, ok := exit[images[i].UniqueID]; !ok {
			addImage = append(addImage, images[i])
		}
	}

	if err = s.imageDal.CreateImage(ctx, images); err != nil {
		logging.Get().Err(err).Interface("image", images).Msg("NodeImageReport CreateImage")
		return err
	}

	if err := s.AddScanTask(ctx, addImage); err != nil {
		logging.Get().Err(err).Interface("image", addImage).Msg("NodeImageReport AddScanTask")
		return err
	}

	return nil
}

func (s *NodeImageReport) AddScanTask(ctx context.Context, newImages []*imagesecModel.Image) error {
	if len(newImages) == 0 {
		return nil
	}

	autoAdd := false
	config, err := s.configDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		logging.Get().Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("NodeImageReport AddScanTask")
	} else {
		autoAdd = config.NodeImageConfig.AutoScanAdded
	}
	if !autoAdd {
		logging.Get().Info().Bool("autoAdd", autoAdd).Msg("AddScanTask")
		return nil
	}

	newImageIds := make([]int64, 0)
	for i := range newImages {
		newImageIds = append(newImageIds, newImages[i].ID)
	}

	if len(newImageIds) > 0 && autoAdd {
		taskInfo := imagesecModel.ImageScanTask{
			ImageFromType: imagesecModel.ImageFromNode,
			ScanType:      imagesecModel.ImageSyncTrigger,
			Status:        imagesecModel.TaskStatusPending,
		}

		param := imagesecModel.ImageListParam{ImageIds: newImageIds, ImageFromType: imagesecModel.ImageFromNode}
		if err := s.scanTaskSrv.CreateImageScanTask(ctx, param, taskInfo); err != nil {
			logging.Get().Err(err).Interface("taskInfo", taskInfo).Msg("CreateImageScanTask")
			return err
		} else {
			logging.Get().Info().Interface("taskInfo", taskInfo).Msg("CreateImageScanTask succeed")
		}
	}
	return nil
}

func (s *NodeImageReport) handleMsg(stopCh <-chan struct{}) error {
	err := s.mqReader.Subscribe(model.NodeImageTopic, model.NodeImageGroup, s.ReceiveAssetReport)
	if err != nil {
		logging.Get().Err(err).Msg("failed to sub message queue")
		return err
	}
	logging.Get().Info().Msg("sub message queue ok")
	<-stopCh
	logging.Get().Info().Msg("sub message queue end")

	return fmt.Errorf("quit message handler")
}

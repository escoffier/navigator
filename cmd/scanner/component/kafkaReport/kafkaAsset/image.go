package kafkaAsset

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	imageMetaSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta/metaGlobal"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
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
	detectTaskSrv detect.ImageDetectTaskService
	NodeImageQ    *ImageQueue
	RegImageQ     *ImageQueue
	RegDal        imagesecStore.RegistryDal
	Log           *scannerUtils.LogEvent
}

var imageReport *ImageReport

func NewImageReport(
	imageDal imagesecStore.ImageMetaDal,
	nodeInfoDal imagesecStore.NodeInfoDal,
	scanResultDal imagesecStore.ScanResultDal,
	mqReader mq.Reader,
	configDal imagesecStore.ScanImageConfigDal,
	scanTaskSrv service.ScanTaskService,
	detectTaskSrv detect.ImageDetectTaskService,
	regDal imagesecStore.RegistryDal,
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
		detectTaskSrv: detectTaskSrv,
		RegDal:        regDal,
		NodeImageQ:    NewImageQueue(consts.SyncScanTaskCheckInterval),
		RegImageQ:     NewImageQueue(consts.SyncScanTaskCheckInterval),
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ImageReport"),
			scannerUtils.WithModule(consts.ModuleKafkaReport),
		),
	}
	s.AddScanTask(context.Background())
	imageReport = s
	return imageReport
}

func (s *ImageReport) ReceiveReport(ctx context.Context) error {

	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("scanner in slave cluster,ignore handle kafka msg")
		return nil
	}

	s.Log.Info().Msg("scanner in main cluster,ready to handle kafka msg")

	ch := make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Stack().Msg("ImageReport")
			}
		}()

		if err := s.handleMsg(ch); err != nil {
			s.Log.Err(err).Msg("finished")
		}
	}()

	s.Log.Info().Msg("receive kafka started end")

	return nil
}

func (s *ImageReport) ReceiveAssetReport(ctx context.Context, msg kafka.Message) error {
	msg.Value = scannerUtils.UnzipByteSlice(msg.Value)

	var report imagesecTypes.NodeReport
	err := json.Unmarshal(msg.Value, &report)

	if err != nil {
		s.Log.Err(err).Msg("failed to unmarshal node image msg")
		return err
	}

	s.Log.Debug().
		Str("uuid", report.UUID).
		Str("clusterKey", report.NodeInfo.ClusterKey).
		Str("node", report.NodeInfo.HostName).
		Str("reg", report.RegInfo.Url+report.RegInfo.Name).
		Int64("reportedAt", report.ReportedAt).
		Interface("report", report).
		Msg("receive image report")

	_ = s.NodeImage(ctx, report)
	_ = s.RegImage(ctx, report)
	return nil
}

func (s *ImageReport) NodeImage(ctx context.Context, imageReport imagesecTypes.NodeReport) error {
	if len(imageReport.NodeImages) == 0 {
		return nil
	}

	images, node, envs := s.GetNodeImageInfo(imageReport)
	if err := node.Check(); err != nil {
		s.Log.Err(err).Msg("node info incorrect")
		return err
	}

	s.Log.Debug().Int("images", len(images)).Int("envs", len(envs)).Msg("ImageMateToModel")

	if err := s.nodeReportDal.CreateNodeInfo(ctx, node); err != nil {
		s.Log.Err(err).Interface("node", node).Msg("CreateNodeInfo")
	}

	for imageID, en := range envs {
		if err := s.scanResultDal.CreateImageEnv(ctx, imageID, en); err != nil {
			s.Log.Err(err).Uint64("imageID", images[0].UniqueID).Msg("CreateImageEnv")
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
		s.Log.Err(err).Str("configType", imagesecModel.ImageFromNode).Msg("SearchImage")
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
		s.Log.Err(err).Interface("image", images).Msg("SearchImage")
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
		s.Log.Err(err).Interface("image", images).
			Msg("CreateNodeImage")
		return err
	}

	_ = s.AddNodeImageScanTask(ctx, addImage)

	// 2.21的新改动，只有扫描之后才做检测
	// _ = s.AddImageDetectTask(ctx, addImage)
	return nil
}

func (s *ImageReport) RegImage(ctx context.Context, imageReport imagesecTypes.NodeReport) error {
	images, envs := GetRegImageInfo(imageReport)

	s.Log.Debug().Int("images", len(images)).
		Int("envs", len(envs)).Msg("ImageMateToModel")

	if len(images) == 0 {
		return nil
	}

	updateChan := imageMetaSrv.GetImageUpdateChan()
	for imageID, en := range envs {
		if err := s.scanResultDal.CreateImageEnv(ctx, imageID, en); err != nil {
			s.Log.Err(err).Uint64("imageID", images[0].UniqueID).
				Msg("CreateImageEnv")
		}
	}

	uniqueIds := make([]uint64, 0)
	for i := range images {
		uniqueIds = append(uniqueIds, images[i].GenUniqueID())
	}
	pre, _, err := s.imageDal.SearchImage(ctx, imagesecModel.ImageDalParam{UniqueIds: uniqueIds})
	if err != nil {
		s.Log.Err(err).Str("configType", imagesecModel.ImageFromNode).
			Msg("SearchImage")
		return err
	}
	exit := make(map[uint64]bool)
	for i := range pre {
		exit[pre[i].UniqueID] = true
	}
	registry, _, err := s.RegDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
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

	addImage := make([]*imagesecModel.Image, 0)
	for i := range images {
		reg, ok := regs[images[i].RegID]
		if !ok {
			continue
		}
		images[i].Host = reg.Url
		if _, ok := exit[images[i].UniqueID]; !ok {
			go func(im *imagesecModel.Image) { updateChan.AddRegImageChan <- im }(images[i])
			addImage = append(addImage, images[i])
		}
	}

	if err = s.imageDal.CreateRegImage(ctx, images); err != nil {
		s.Log.Err(err).Interface("image", images).
			Msg("CreateRegImage")
		return err
	}

	_ = s.AddRegImageScanTask(ctx, addImage)
	// 2.21的新改动，只有扫描之后才做检测
	// _ = s.AddImageDetectTask(ctx, addImage)

	return nil
}

func (s *ImageReport) AddNodeImageScanTask(ctx context.Context, newImages []*imagesecModel.Image) error {
	if len(newImages) == 0 {
		return nil
	}
	autoAdd := false
	config, err := s.configDal.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		s.Log.Err(err).Str("configType", imagesecModel.ConfigTypeNodeScanImage).Msg("CreateScanTask")
	} else {
		autoAdd = config.ImageScanConfig.AutoScanAdded
	}
	if !autoAdd {
		s.Log.Info().Bool("autoAdd", autoAdd).Msg("CreateScanTask")
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
		s.Log.Err(err).Str("configType", imagesecModel.ConfigTypeRegScanImage).
			Msg("CreateScanTask")
	} else {
		autoAdd = config.ImageScanConfig.AutoScanAdded
	}
	if !autoAdd {
		s.Log.Info().Bool("autoAdd", autoAdd).
			Msg("CreateScanTask")
		return nil
	}

	for i := range newImages {
		s.RegImageQ.Add(newImages[i])
	}

	return nil
}

func (s *ImageReport) AddImageDetectTask(ctx context.Context, newImages []*imagesecModel.Image) error {
	if len(newImages) == 0 {
		return nil
	}
	uniqueIds := make([]uint64, 0)
	for i := range newImages {
		uniqueIds = append(uniqueIds, newImages[i].UniqueID)
	}

	imageSearchParam := imagesecModel.ImageSearchApiParam{
		ImageUniqueIds: uniqueIds,
	}
	if err := s.detectTaskSrv.CreateImageDetectTask(ctx,
		imageSearchParam,
		imagesecModel.ImageDetectTask{Priority: imagesecModel.DetectAddImage},
		nil,
	); err != nil {
		logging.Get().Err(err).Msg("updateImageInReg CreateDetectTask")
		return err
	}

	return nil
}

func (s *ImageReport) handleMsg(stopCh <-chan struct{}) error {
	err := s.mqReader.Subscribe(consts.NodeImageTopic, consts.NodeImageGroup, s.ReceiveAssetReport)
	if err != nil {
		s.Log.Err(err).Msg("failed to sub message queue")
		return err
	}
	s.Log.Info().Msg("sub message queue ok")
	<-stopCh
	s.Log.Info().Msg("sub message queue end")

	return fmt.Errorf("quit message handler")
}

func (s *ImageReport) AddScanTask(ctx context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("module", "KafkaReport").Msg("AddScanTask")
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

			param := imagesecModel.ImageSearchApiParam{ImageUniqueIds: ims, ImageFromType: imagesecModel.ImageFromRegistry}
			if err := s.scanTaskSrv.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				s.Log.Err(err).Interface("taskInfo", taskInfo).Msg("CreateScanTask")
				continue
			}
			s.Log.Info().Interface("taskInfo", taskInfo).Msg("CreateScanTask succeed")
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("module", "KafkaReport").Msg("AddScanTask")
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

			param := imagesecModel.ImageSearchApiParam{ImageUniqueIds: ims, ImageFromType: imagesecModel.ImageFromNode}
			if err := s.scanTaskSrv.CreateImageScanTask(ctx, param, taskInfo); err != nil {
				s.Log.Err(err).Interface("taskInfo", taskInfo).Msg("CreateScanTask")
				continue
			}
			s.Log.Info().Interface("taskInfo", taskInfo).Msg("CreateScanTask succeed")
		}
	}()
}

func (s *ImageReport) GetNodeImageInfo(data imagesecTypes.NodeReport) ([]*imagesecModel.Image, *imagesecModel.NodeInfo,
	map[uint64][]*imagesecModel.ImageEnv) {
	//  contanerd 会有这样的数据，要处理
	//  digests=["docker.io/maohaoxin/syslog_upd_app_linux@sha256:b2d3f7e9af1d16382539dc3c330acc7d2d5cd2109d0eeff0f60679769bc91f55"]
	//  imageId=sha256:f66e9f553ba9899c5802abc1ebd9868f7bebe7bee406b5489d47550b8b15c210
	//  repoTags=["sha256:f66e9f553ba9899c5802abc1ebd9868f7bebe7bee406b5489d47550b8b15c210"]
	/*
		digests=["docker.io/573320328/liuqianli@sha256:c57b291c4f0f9b4b17cf56a4628b25c323a811d1784a89f66b1379bbaeb5599d"]
			imageId=docker.io/573320328/liuqianli:v9
					repoTags=["docker.io/573320328/liuqianli:v9"]
					uuid=db336be30e3c4f4daf8704560a898072
	*/

	images := make([]*imagesecModel.Image, 0)
	envs := make(map[uint64][]*imagesecModel.ImageEnv)

	node := &imagesecModel.NodeInfo{
		IP:         data.NodeInfo.Ip,
		Hostname:   data.NodeInfo.HostName,
		ClusterKey: data.NodeInfo.ClusterKey,
		// AviraDB:    data.ReportDBVersion.AviraDBVersion, todo(下期功能)
	}

	node.UniqueID = node.GenUniqueID()

	for _, image := range data.NodeImages {
		im := &imagesecModel.Image{
			Namespace:     image.Namespace,
			ImageFromType: imagesecModel.ImageFromNode,
			ImageID:       image.ImageId,
			Size:          image.Size,
			Layer:         image.Layers,
			BuildAt:       GetBuildAt(image.Created),
			User:          image.User,
			NodeID:        node.UniqueID,
			Heartbeat:     time.Now().UnixMilli(),
		}
		split := strings.Split(image.Os, ":")
		if len(split) >= 2 {
			im.OS = types.OS{Family: split[0], Name: split[1], Eosl: false} // Eosl 表示不再维护
		}

		// 对于重复构建的相同名的镜像，前一次的镜像只有ID，没有repoTags,但是可以通过这个ID运行起容器
		if len(image.RepoTags) == 0 {
			im.Serialize()
			images = append(images, im)

			envs[im.UniqueID] = append(envs[im.UniqueID], ParseImageEnv(im.UniqueID, image.ENVS)...)
		}

		for _, repoTag := range image.RepoTags {
			host, repo, tag := scannerUtils.ParseImageName(repoTag)
			// im.ImageName 一定要保持原样，不然在扫描时会找不到镜像
			im.Host, im.Repo, im.Tag, im.Project, im.ImageName = host, repo, tag, GetProject(repo), repoTag

			// 本地镜像没有推送到仓库，是没有digest的
			if len(image.Digests) == 0 {
				im2 := im.DeepCopy()
				im2.Serialize()
				images = append(images, im2)
				envs[im2.UniqueID] = append(envs[im2.UniqueID], ParseImageEnv(im2.UniqueID, image.ENVS)...)
			}
			for _, digest := range image.Digests {
				im.Digest = scannerUtils.GetSha256Digest(digest)
				im2 := im.DeepCopy()
				im2.Serialize()
				images = append(images, im2)
				envs[im2.UniqueID] = append(envs[im2.UniqueID], ParseImageEnv(im2.UniqueID, image.ENVS)...)
				images = append(images, im.DeepCopy())
			}
		}
	}

	ans := make([]*imagesecModel.Image, 0)
	for i := range images {
		if err := images[i].Check(); err != nil {
			s.Log.Debug().Interface("image", images[i]).Msg("image check")
			continue
		}
		ans = append(ans, images[i])
	}

	return ans, node, envs
}

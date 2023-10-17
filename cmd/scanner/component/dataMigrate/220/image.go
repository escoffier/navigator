package ver220

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	migrateTypes "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dataMigrate/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecType "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type ImageMigrate struct {
	MqWriter        mq.Writer
	DataMigrateDal  imagesecStore.DataMigrateDal
	RegDal          imagesecStore.RegistryDal
	ScanIssueDal    imagesecStore.ScanIssueDal
	ScanResultDal   imagesecStore.ScanResultDal
	PreImageService migrateTypes.ImageService // 原来老表的逻辑
	ImageDal        store.ImageDal
	ImageMetaDal    imagesecStore.ImageMetaDal
	PolicyDal       imagesecStore.DetectPolicyDal
	Log             *scannerUtils.LogEvent
}

var imageMigrate *ImageMigrate

func GetImageMigrate() (*ImageMigrate, error) {
	if imageMigrate != nil {
		return imageMigrate, nil
	}

	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Str("module", "migrate").Msg("failed to create mq reader")
		return nil, err
	}
	rdbInstance := store.GetRDBInstance()
	scanResultDal := imagesecStore.NewScanResultDao(rdbInstance)

	imageDal := store.NewScannerOrm(rdbInstance)
	dataMigrateDal := imagesecStore.NewDataMigrateDao(rdbInstance)
	scanIssueDal := imagesecStore.NewScanIssueDao(rdbInstance)
	imageMetaDal := imagesecStore.NewImageMetaDao(rdbInstance)
	policyDal := imagesecStore.NewDetectPolicyDao(rdbInstance)
	regDal := imagesecStore.NewRegistryDao(rdbInstance)
	preLib := imagemeta.NewPreLibImageSrv()

	imageMigrate = NewImageMate(
		mqWriter,
		dataMigrateDal,
		regDal,
		scanResultDal,
		preLib,
		imageDal,
		scanIssueDal,
		imageMetaDal,
		policyDal,
	)
	return imageMigrate, nil
}

func NewImageMate(
	mqWriter mq.Writer,
	dataMigrateDal imagesecStore.DataMigrateDal,
	regDal imagesecStore.RegistryDal,
	scanResultDal imagesecStore.ScanResultDal,
	imageService migrateTypes.ImageService, // 原来老表的逻辑
	imageDal store.ImageDal,
	scanIssueDal imagesecStore.ScanIssueDal,
	imageMetaDal imagesecStore.ImageMetaDal,
	policyDal imagesecStore.DetectPolicyDal,
) *ImageMigrate {

	s := &ImageMigrate{
		MqWriter:        mqWriter,
		DataMigrateDal:  dataMigrateDal,
		RegDal:          regDal,
		ScanIssueDal:    scanIssueDal,
		ScanResultDal:   scanResultDal,
		PreImageService: imageService,
		ImageDal:        imageDal,
		ImageMetaDal:    imageMetaDal,
		PolicyDal:       policyDal,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("2.20"),
			scannerUtils.WithModule(consts.ModuleMigrate)),
	}
	return s
}

func (s *ImageMigrate) MigrateImage(ctx context.Context, imageID int64, subtaskID int64) error {
	registry, _, err := s.RegDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
	if err != nil {
		s.Log.Err(err).Msg("MigrateImage")
		return err
	}
	if len(registry) == 0 {
		return nil
	}
	retIds := make([]int64, 0)
	for i := range registry {
		retIds = append(retIds, registry[i].ID)
	}
	images, _, err := s.ImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{
		ImageFromType: imagesecModel.ImageFromRegistry,
		NotCount:      true,
		InIds:         []int64{imageID},
		RegIds:        retIds,
	}, nil)
	if err != nil {
		s.Log.Err(err).Msg("MigrateImage")
		return err
	}
	if len(images) == 0 {
		s.Log.Info().Int64("imageID", imageID).Msg("MigrateImage not find image")
		return err
	}

	imageMeta := DataToImage(images[0])

	err = s.ImageMetaDal.CreateRegImage(ctx, imageMeta)

	if err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("CreateRegImage failed")
		return err
	}
	nr := ToNodeReport(images[0])
	if err := s.sendImageToKafka(ctx, nr); err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("MigrateImage sendImageToKafka")
		return err
	}
	data, err := s.PreImageService.GetImageCorrelateData(ctx, imagesecModel.ImageAssociateParam{
		ImageFromType:   imagesecModel.ImageFromRegistry,
		ImageId:         imageID,
		ImageUniqueID:   images[0].UniqueImage,
		VulnEnable:      true,
		MalwareEnable:   true,
		PkgEnable:       true,
		SensitiveEnable: true,
		WebshellEnable:  true,
	})
	if err != nil {
		s.Log.Err(err).Msg("GetImageCorrelateData failed")
		return err
	}

	vulnIssue := GetVulnToImage(data)
	pkgIssue := GetPkgToImage(data)

	if err := s.ScanResultDal.CreatePkg(ctx, data.Pkg); err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("MigrateImage CreatePkg")
	}

	if err := s.ScanIssueDal.CreateVulnToImage(ctx, imagesecModel.CreateVulnToImageParam{
		ImageUniqueID: data.Image.UniqueID,
		Data:          vulnIssue,
	}); err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("MigrateImage CreateVulnToImage")
	}

	if err := s.ScanIssueDal.CreatePkgToImage(ctx, imagesecModel.CreatePkgToImageParam{
		ImageUniqueID: data.Image.UniqueID,
		Data:          pkgIssue,
	}); err != nil {
		s.Log.Err(err).Msg("MigrateImage CreatePkgToImage")
	}

	scanRes := ToScanResult(data, subtaskID)
	scanRes.ImageUniqueID = data.Image.UniqueID
	_ = s.sendScanResultToKafka(ctx, scanRes)

	s.Log.Info().Int64("imageID", imageID).Str("imageName", data.Image.GetImageName()).Msg("MigrateImage success")
	return nil
}

func DataToImage(image model.ImageList) []*imagesecModel.Image {
	res := make([]*imagesecModel.Image, 0)

	im := &imagesecModel.Image{
		ImageFromType: imagesecModel.ImageFromRegistry,
		Host:          image.Library,
		Repo:          image.FullRepoName,
		Tag:           image.Tags,
		ImageName:     image.GetImageName(),
		Digest:        image.Digest,
		Size:          int64(image.Size),
		LayerStr:      strings.Join(strings.Split(image.Layers, "|"), ","),
		Layer:         getLayers(image),
		User:          image.GetBootUser(),
		Flag:          image.Flag,
		ImageUUID:     image.ImageUUID,
		RegID:         image.RegistryID,
		Project:       image.Project,
		Heartbeat:     time.Now().UnixMilli(),
	}
	var osInfo types.OS
	if err := json.Unmarshal([]byte(image.OS), &osInfo); err == nil {
		im.OS = osInfo
	}
	if err := im.Check(); err == nil {
		res = append(res, im)
	}
	return res
}

func (s *ImageMigrate) MigrateExitData(ctx context.Context, ver string) error {

	s.Log.Info().Msg("Migrate MigrateExitData start")

	migrate, err := s.DataMigrateDal.SearchDataMigrate(ctx,
		imagesecModel.SearchDataMigrateParam{SoftVersion: ver, Model: consts.DataMigrateModelImage})
	if err != nil {
		return err
	}
	if len(migrate) == 0 || migrate[0].FinishedAt > 0 {
		return nil
	}
	mi := migrate[0]
	var lastID int64
	if i, err := strconv.ParseInt(mi.Last, 10, 64); err == nil {
		lastID = i
	}

	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortAsc().SetSortFiledByID()

	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	cnt := 0
	for {
		<-ticker.C
		images, _, err := s.ImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{
			ImageFromType: imagesecModel.ImageFromRegistry,
			StartID:       lastID,
			NotCount:      true,
		}, filter)
		if err != nil {
			s.Log.Err(err).Str("SOFT_VERSION", ver).Msg("Migrate")
			return err
		}
		if len(images) == 0 {
			updater := map[string]interface{}{"finished_at": time.Now().UnixMilli()}
			_ = s.DataMigrateDal.UpdateDataMigrate(ctx, mi.ID, updater)
			s.Log.Err(err).Str("SOFT_VERSION", ver).Msg("Migrate finished")
			break
		}
		cnt += len(images)
		lastID = images[len(images)-1].ID
		for i := range images {
			image := images[i]
			_ = s.MigrateImage(ctx, image.ID, 0)
		}
		updater := map[string]interface{}{"last": fmt.Sprintf("%d", lastID)}
		_ = s.DataMigrateDal.UpdateDataMigrate(ctx, mi.ID, updater)
	}
	s.Log.Info().Int("imageCnt", cnt).Msg("Migrate MigrateExitData end")
	return nil
}

func (s *ImageMigrate) Migrate(ctx context.Context, ver string) error {
	_ = s.MigrateExitData(ctx, ver)
	_ = s.SyncImageMeta(ctx, ver)
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
		Digests:  []string{image.Digest},
		RepoTags: []string{image.GetImageName()},
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

func GenImageUniqueID(data imagesecType.NodeReport) uint64 {
	images := make([]*imagesecModel.Image, 0)

	for _, image := range data.RegImages {
		im := &imagesecModel.Image{
			ImageFromType: imagesecModel.ImageFromRegistry,
			RegID:         data.RegInfo.RegID,
		}

		for _, repoTag := range image.RepoTags {
			host, repo, tag := scannerUtils.ParseImageName(repoTag)
			im.Host, im.Repo, im.Tag = host, repo, tag
		}
	}

	if len(images) > 0 {
		images[0].ImageName = images[0].GetImageName()
		return images[0].GenUniqueID()
	}
	return 0
}

func ToScanResult(data *imagesecModel.ImageWithCorrelateData2, subtaskID int64) imagesecType.ScanResult {
	sensitiveFiles := make([]imagesecType.SensitiveFile, 0)
	for _, sens := range data.Sensitive {
		se := imagesecType.SensitiveFile{
			Filename:      sens.Filename,
			DescriptionEn: sens.DescriptionEn,
			DescriptionZh: sens.DescriptionZh,
		}
		sensitiveFiles = append(sensitiveFiles, se)
	}

	avira := make([]imagesecType.ClamAvScanResult, 0)

	for i := range data.Malware {
		mal := data.Malware[i]
		ma := imagesecType.ClamAvScanResult{
			Filename:     mal.Filename, // todo
			Hash:         mal.Hash,
			MalwareNames: []string{mal.Name},
		}
		avira = append(avira, ma)
	}

	webshell := make([]imagesecType.HmWebshell, 0)

	for _, wb := range data.Webshell {
		mod := strings.Join([]string{wb.Mod.User, wb.Mod.Group, wb.Mod.Perm}, " ")
		size, _ := strconv.ParseInt(wb.Size, 10, 64)
		web := imagesecType.HmWebshell{
			Filename:            wb.Filename, // todo
			MD5:                 wb.MD5,
			Mod:                 mod,
			Size:                size,
			Code:                wb.CodeContent(),
			RiskLevel:           wb.RiskLevel,
			Description:         wb.Description,
			FilePathInContainer: wb.Filepath,
		}
		webshell = append(webshell, web)
	}

	res := imagesecType.ScanResult{
		TaskID:      0,
		SubTaskID:   subtaskID,
		OS:          data.Image.OS,
		VulnResults: nil, // 直接入库
		Sensitives:  imagesecType.SensitiveFileResults{SensitiveFiles: sensitiveFiles},
		Malwares:    imagesecType.MalwareResults{ClamAvScanResults: avira},
		Webshells:   imagesecType.WebshellResults{HmWebshells: webshell},
	}
	return res
}

func GetVulnToImage(data *imagesecModel.ImageWithCorrelateData2) []*imagesecModel.VulnToImage {
	res := make([]*imagesecModel.VulnToImage, 0)
	for i := range data.Vuln {
		ti := &imagesecModel.VulnToImage{
			UniqueTarget:  data.Vuln[i].UniqueID,
			ImageUniqueID: data.Image.UniqueID,
		}
		res = append(res, ti)
	}
	return res
}

func GetPkgToImage(data *imagesecModel.ImageWithCorrelateData2) []*imagesecModel.PkgToImage {
	issue := make([]*imagesecModel.PkgToImage, 0)
	for i := range data.Pkg {
		pk := &imagesecModel.PkgToImage{
			UniqueTarget:  data.Pkg[i].GenUniqueID(),
			ImageUniqueID: data.Image.UniqueID,
		}
		issue = append(issue, pk)
	}
	return issue
}

func getLayers(im model.ImageList) []imagesecType.Layer {
	layers := make([]imagesecType.Layer, 0)
	if im.ManifestV2 == nil {
		return layers
	}

	for _, layer := range im.ManifestV2.Layers {
		newLayer := imagesecType.Layer{
			Size:   layer.Size,
			Digest: layer.Digest,
		}
		layers = append(layers, newLayer)
	}
	return layers
}

func (s *ImageMigrate) sendImageToKafka(ctx context.Context, report imagesecType.NodeReport) error {

	bys, err := json.Marshal(report)
	if err != nil {
		s.Log.Err(err).Msg("Marshal")
		return err
	}
	msg := kafka.Message{
		Topic: model.NodeImageTopic,
		Key:   []byte(model.NodeImageKey),
		Value: bys,
	}

	if err := s.MqWriter.Write(ctx, msg.Topic, msg); err != nil {
		s.Log.Err(err).Msg("SyncAllImage SendToMq")
		return err
	}
	s.Log.Info().Msg("send kafka image end")
	return nil
}

func (s *ImageMigrate) sendScanResultToKafka(ctx context.Context, scanResult imagesecType.ScanResult) error {
	sendData, err := json.Marshal(scanResult)
	if err != nil {
		s.Log.Err(err).Msg("failed to marshal scanResult")
		return err
	}
	err = s.MqWriter.Write(context.Background(),
		model.NodeImageScanResultTopic,
		kafka.Message{
			Key:   []byte(model.NodeImageScanResultKey),
			Value: sendData,
		})
	if err != nil {
		s.Log.Err(err).Msg("failed to send result to kafka")
		return err
	}
	s.Log.Info().Msg("send kafka scan result end")
	return nil
}

func (s *ImageMigrate) SyncImageMeta(ctx context.Context, ver string) error {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Str("Stack", string(debug.Stack())).Msg("Migrate SyncImageMeta")
			}
		}()

		ticker := time.NewTicker(time.Minute * 30)
		defer ticker.Stop()
		for {
			<-ticker.C
			_ = s.syncImageMeta(ctx)
			ticker.Reset(time.Minute * 30)
		}
	}()
	return nil
}

func (s *ImageMigrate) syncImageMeta(ctx context.Context) error {
	s.Log.Info().Msg("Migrate SyncImageMeta start")

	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit).SetSortDesc().SetSortFiled("updated_at")

	layout := "2006-01-02 15:04:05.000000"
	thirtyAgoStr := time.Now().Add(-30 * time.Minute).Format(layout) // 30分钟前的时间str
	thirtyAgo, err := time.Parse(layout, thirtyAgoStr)               // 把str转为time.Time格式，才能进行数据库查询

	timeNowStr := time.Now().Format(layout)
	lastTime, err := time.Parse(layout, timeNowStr)
	if err != nil {
		s.Log.Err(err).Msg("SyncImageMeta time Parse failed")
		return err
	}
	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()
	cnt := 0
	for {
		<-ticker.C

		registry, _, err := s.RegDal.SearchRegistry(ctx, imagesecModel.SearchRegistryParam{Deleted: consts.FalseString})
		if err != nil {
			s.Log.Err(err).Msg("MigrateImage")
			continue
		}
		if len(registry) == 0 {
			continue
		}
		retIds := make([]int64, 0)
		for i := range registry {
			retIds = append(retIds, registry[i].ID)
		}

		images, _, err := s.ImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{
			ImageFromType: imagesecModel.ImageFromRegistry,
			StartTime:     lastTime,
			NotCount:      true,
			RegIds:        retIds,
		}, filter)

		if err != nil {
			s.Log.Err(err).Msg("SyncImageMeta failed")
			return err
		}
		if len(images) == 0 {
			s.Log.Err(err).Msg("SyncImageMeta finished")
			break
		}
		lastTime = images[len(images)-1].UpdatedAt

		flag := false // 标记是否扫描到30分钟之前得镜像

		res := make([]*imagesecModel.Image, 0)

		for _, image := range images {
			if image.UpdatedAt.Before(thirtyAgo) {
				flag = true
				break
			}
			res = append(res, DataToImage(image)...)
		}
		cnt += len(images)
		if err := s.ImageMetaDal.CreateRegImage(ctx, res); err != nil {
			s.Log.Err(err).Msg("Migrate SyncImageMeta CreateRegImage failed")
			continue
		}
		if flag {
			break
		}
	}

	s.Log.Info().Int("syncImageCnt", cnt).Msg("Migrate SyncImageMeta end")
	return nil
}

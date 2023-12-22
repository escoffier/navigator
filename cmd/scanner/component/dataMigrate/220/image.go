package ver220

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
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
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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
		err1 := fmt.Errorf("failed to create mq reader:%s", err.Error())
		return nil, err1
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

func (s *ImageMigrate) MigrateImage(ctx context.Context, imageID int64) error {
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
	images, _, err := s.ImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{InIds: []int64{imageID}}, nil)
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

func (s *ImageMigrate) MigrateScan(ctx context.Context, imageID int64, subtaskID int64) error {

	data, vulns, err := s.PreImageService.GetImageCorrelateData(ctx, imageID)

	if err != nil {
		s.Log.Err(err).Msg("GetImageCorrelateData failed")
		return err
	}

	// 漏洞和软件包的数据要直接入库
	vulnIssue := GetVulnToImage(data)
	pkgIssue := GetPkgToImage(data)

	s.Log.Err(err).Int64("imageID", imageID).Int("vulnIssue", len(vulnIssue)).Int("pkgIssue", len(pkgIssue)).
		Int("vuln", len(vulns)).Int("pkg", len(data.Pkg)).Msg("MigrateImage")

	if err := s.ScanResultDal.CreatePkg(ctx, data.Pkg); err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("MigrateImage CreatePkg")
	}
	if err := s.ScanResultDal.CreateVuln(ctx, imagesecModel.CreateVulnParam{
		OnlineVuln: false,
		Data:       vulns,
	}); err != nil {
		s.Log.Err(err).Int64("imageID", imageID).Msg("MigrateImage vuln")
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

	// 其他的数据发 kafka
	_ = s.sendScanResultToKafka(ctx, scanRes)

	s.Log.Info().Int64("imageID", imageID).Str("imageName", data.Image.GetImageName()).Msg("MigrateImage success")
	return nil
}

func (s *ImageMigrate) Migrate(ctx context.Context, ver string) error {
	// _ = s.MigrateExitData(ctx, ver)
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
			Filename:            wb.Filename,
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
		IgnoreVulnAndPkg: true,
		SubTaskID:        subtaskID,
		OS:               data.Image.OS,
		Sensitives:       imagesecType.SensitiveFileResults{SensitiveFiles: sensitiveFiles},
		Malwares:         imagesecType.MalwareResults{ClamAvScanResults: avira},
		Webshells:        imagesecType.WebshellResults{HmWebshells: webshell},
	}
	return res
}

func GetVulnToImage(data *imagesecModel.ImageWithCorrelateData2) []*imagesecModel.VulnToImage {

	res := make([]*imagesecModel.VulnToImage, 0)

	im := data.Image
	im.ImageFromType = imagesecModel.ImageFromRegistry

	iuid := im.GenUniqueID()

	for i := range data.Vuln {
		vu := data.Vuln[i]
		pkg := imagesecModel.Pkg{
			Name:    vu.PkgName,
			Version: vu.PkgVersion,
		}
		puid := pkg.GenUniqueID()
		vu2 := imagesecModel.Vuln{Name: data.Vuln[i].Name, PkgUniqueID: puid}
		vuid := vu2.GenUniqueID()

		ti := &imagesecModel.VulnToImage{
			UniqueTarget:  vuid,
			ImageUniqueID: iuid,
		}
		res = append(res, ti)
	}
	return res
}

func GetPkgToImage(data *imagesecModel.ImageWithCorrelateData2) []*imagesecModel.PkgToImage {

	im := data.Image
	im.ImageFromType = imagesecModel.ImageFromRegistry
	iuid := im.GenUniqueID()

	issue := make([]*imagesecModel.PkgToImage, 0)
	for i := range data.Pkg {
		vu := data.Pkg[i]
		pkg := imagesecModel.Pkg{
			Name:    vu.Name,
			Version: vu.Version,
		}
		puid := pkg.GenUniqueID()

		pk := &imagesecModel.PkgToImage{
			UniqueTarget:  puid,
			ImageUniqueID: iuid,
		}
		issue = append(issue, pk)
	}
	return issue
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

		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			_ = s.syncImageMeta(ctx)
		}
	}()
	return nil
}

func (s *ImageMigrate) syncImageMeta(ctx context.Context) error {
	s.Log.Info().Msg("Migrate SyncImageMeta start")

	filter := model.EmptyFilter().SetLimit(consts.DefaultMaxLimit)

	ticker := time.NewTicker(time.Second * 5)
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
			ticker.Reset(time.Minute * 2)
			continue
		}
		regs := make(map[int64]imagesecModel.Registry)
		retIds := make([]int64, 0)
		for i := range registry {
			retIds = append(retIds, registry[i].ID)
			regs[registry[i].ID] = registry[i]
		}

		images, _, err := s.ImageDal.SearchImage(ctx, imagesecModel.SearchImageParam{
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
			s.Log.Info().Msg("SyncImageMeta this batch finished")
			break
		}
		for i := range images {
			if images[i].Status != 0 {
				continue
			}
			_ = s.MigrateImage(ctx, images[i].ID)
		}
		s.Log.Info().Int("syncImageCnt", len(images)).Msg("Migrate SyncImageMeta")
	}

	s.Log.Info().Int("syncImageCnt", cnt).Msg("Migrate SyncImageMeta end")
	return nil
}

func (s *ImageMigrate) updateImageAdapted(ctx context.Context, imageID int64) error {
	updater := map[string]interface{}{
		"status": consts.ImageStatusImageAdapted,
	}
	err := s.ImageDal.UpdateImage(ctx, fmt.Sprintf("id = %d", imageID), updater, nil)
	if err != nil {
		s.Log.Err(err).Msg("updateImageAdapted")
		return err
	}
	return nil
}

// 和运维商量，中移环境不关心老数据，重新扫描
func (s *ImageMigrate) MigrateExitData(ctx context.Context, ver string) error {

	s.Log.Info().Msg("Migrate MigrateExitData start")

	migrate, err := s.DataMigrateDal.SearchDataMigrate(ctx,
		imagesecModel.SearchDataMigrateParam{SoftVersion: consts.ScannerVersion220, Model: consts.DataMigrateModelImage})
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
			_ = s.MigrateImage(ctx, image.ID)
			// _ = s.MigrateScan(ctx, image.ID, 0)
		}
		updater := map[string]interface{}{"last": fmt.Sprintf("%d", lastID)}
		_ = s.DataMigrateDal.UpdateDataMigrate(ctx, mi.ID, updater)
	}
	s.Log.Info().Int("imageCnt", cnt).Msg("Migrate MigrateExitData end")
	return nil
}

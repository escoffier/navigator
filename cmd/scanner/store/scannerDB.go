package store

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScannerDB struct {
	RDB *databases.RDBInstance
}

func NewScannerDB(rdb *databases.RDBInstance) *ScannerDB {
	return &ScannerDB{
		RDB: rdb,
	}
}

func (scdb *ScannerDB) InsertToScanWhitelist(ctx context.Context, whitelist *model.ScanWhitelist) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	res, err := scdb.SearchScanWhitelist(ctx, whitelist)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("SearchScanWhitelist error:")
		return err
	}
	if res.Digest != "" {
		if err := scdb.RDB.Get().WithContext(ctx).Where("digest = ?", whitelist.Digest).UpdateColumns(whitelist).Error; err != nil {
			logging.GetLogger().Error().Err(err).Msgf("update whitelist error:")
			return err
		}
	} else {
		if err := scdb.RDB.Get().WithContext(ctx).Create(whitelist).Error; err != nil {
			logging.GetLogger().Error().Err(err).Msgf("update whitelist error:")
			return err
		}
	}

	return nil
}

func (scdb *ScannerDB) SearchScanWhitelist(ctx context.Context, whitelist *model.ScanWhitelist) (*model.ScanWhitelist, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	res := model.ScanWhitelist{}
	if err := scdb.RDB.Get().WithContext(ctx).Select("digest").Where("digest = ?", whitelist.Digest).Find(&res).Error; err != nil {
		logging.GetLogger().Error().Err(err).Msgf("SearchScanWhitelist error:")
		return nil, err
	}
	return &res, nil
}

func (scdb *ScannerDB) InsertToScanImage(ctx context.Context, scanImage *model.ScanImage) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	tmp := make([]model.ScanImage, 0)
	scanImage.Serialize()
	scanImage.CheckSum = scanImage.GetCheckSum()

	if err := scdb.RDB.Get().WithContext(ctx).Select("id", "image_id", "check_sum").Where("image_id = ?", scanImage.ImageID).Find(&tmp).Error; err != nil {
		return err
	}

	if len(tmp) == 0 {
		return scdb.RDB.Get().WithContext(ctx).Create(scanImage).Error
	}
	if tmp[0].CheckSum == scanImage.CheckSum {
		logging.GetLogger().Debug().Int64("ImageID", scanImage.ImageID).Msg("扫描结果没有变动")
		return nil
	}
	return scdb.UpdateToScanImage(ctx, scanImage, tmp[0].ID)
}

func (scdb *ScannerDB) UpdateToScanImage(ctx context.Context, ScanImage *model.ScanImage, tableID int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	err := scdb.RDB.Get().WithContext(ctx).Model(&model.ScanImage{}).Where("id = ?", tableID).Select("*").Omit("id", "created_at").Updates(ScanImage).Error
	if err != nil {
		logging.GetLogger().Err(err).Int64("ImageId", tableID).Msg("UpdateToScanImage Update")
		return err
	}
	return nil
}

func (scdb *ScannerDB) GetImageID(ctx context.Context, digest string, fullRepoName string) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	var tmp model.ImageList
	res := scdb.RDB.Get().WithContext(ctx).Where("digest = ? and full_repo_name= ?", digest, fullRepoName).First(&tmp)
	if res.Error != nil {
		return -1, res.Error
	}
	return tmp.ID, nil
}

func (scdb *ScannerDB) InsertToWebFrame(ctx context.Context, webFrameScan *model.WebFrameScan) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	tmp := model.WebFrameScan{}
	err := scdb.RDB.Get().WithContext(ctx).Where("image_uuid = ?", webFrameScan.ImageUUID).Find(&tmp).Error
	if err != nil {
		return err
	}
	if tmp.ID != 0 {
		err := scdb.RDB.Get().WithContext(ctx).Model(&model.WebFrameScan{}).Where("image_uuid = ?", webFrameScan.ImageUUID).Omit("created_at").Update("web_frame_info", webFrameScan.WebFrameInfoJSON).Error
		if err != nil {
			return err
		}
	} else {
		err := scdb.RDB.Get().WithContext(ctx).Create(webFrameScan).Error
		if err != nil {
			return err
		}
	}
	return nil
}

func (scdb *ScannerDB) InsertToVuln(ctx context.Context, vuln *model.Vuln, imageID int64) error {
	vuln.Serialize()
	vuln.Deserialize()
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	vuln.CheckSum = vuln.GenCheckSum()
	vuln.UniqueVuln = vuln.GenUniqueVuln()

	db := scdb.RDB.Get().WithContext(ctx)
	tmp := make([]model.Vuln, 0)
	if err := db.Model(new(model.Vuln)).Where("unique_vuln = ?", vuln.UniqueVuln).Find(&tmp).Error; err != nil {
		return err
	}
	// 如果没有就新增加
	if len(tmp) == 0 {
		if err := db.Model(new(model.Vuln)).Create(vuln).Error; err != nil {
			return err
		}
	}
	if len(tmp) > 0 {
		if tmp[0].CheckSum != vuln.CheckSum {
			if err := db.Model(new(model.Vuln)).Where("id = ?", tmp[0].ID).Updates(vuln).Error; err != nil {
				return err
			}
		} else {
			logging.GetLogger().Debug().Uint64("UniqueVuln", vuln.UniqueVuln).Msg("vuln未变动")
		}
	}
	// 写入vuln_image表
	vulnImage := model.VulnImage{UniqueVuln: vuln.UniqueVuln, ImageId: imageID}
	if err := db.Model(new(model.VulnImage)).Create(&vulnImage).Error; err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) { // 说明已经扫描过
			return nil
		}
		return err
	}

	return nil
}

func (scdb *ScannerDB) InsertToScanLayer(ctx context.Context, data *model.ScanLayer) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	data.Serialize()
	data.Deserialize()

	tmp := model.ScanLayer{}
	res := scdb.RDB.Get().WithContext(ctx).Where("layer_digest = ? AND image_id= ?", data.LayerDigest, data.ImageID).First(&tmp)
	if res.Error == nil {
		return scdb.RDB.Get().WithContext(ctx).Where("layer_digest = ? AND image_id= ?", data.LayerDigest, data.ImageID).Select("*").Omit("id", "created_at").Updates(&data).Error
	}
	return scdb.RDB.Get().WithContext(ctx).Create(&data).Error
}

func (scdb *ScannerDB) DeleteScanLayer(ctx context.Context, imageIds []int64) error {
	if len(imageIds) == 0 {
		return nil
	}

	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	db := scdb.RDB.Get().WithContext(ctx).Model(&model.ScanLayer{}).Where("image_id IN ?", imageIds)

	return db.Delete(&model.ScanLayer{}).Error
}

func (scdb *ScannerDB) FindRegistryFromURL(ctx context.Context, url string) model.Registry {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	tmp := model.Registry{}
	resRegis := model.Registry{}
	tmp.Url = url
	res := scdb.RDB.Get().WithContext(ctx).Model(tmp).First(&resRegis)
	if res.Error != nil {
		return model.Registry{}
	}
	return resRegis
}

func (scdb *ScannerDB) FindRegistryAll(ctx context.Context) model.Registry {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	tmp := model.Registry{}
	resRegis := model.Registry{}
	res := scdb.RDB.Get().WithContext(ctx).Model(tmp).Last(&resRegis)
	if res.Error != nil {
		return model.Registry{}
	}
	return resRegis
}

func (scdb *ScannerDB) InsertToRegistry(ctx context.Context, registry *model.Registry) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	// fmt.Println("初始化时加密前的密码:", string(Registry.Password))
	encryPass, err := util.DesEncrypt(registry.Password, []byte(consts.EncryptPasswordKey))
	if err != nil {
		logging.GetLogger().Err(err).Msg("NewCipher Error")
	}
	registry.Password = encryPass
	/*decryPass := make([]byte, 1024)
	decryPass, err = scdb.DesDecrypt(encryPass, key)
	fmt.Println("初始化时解压后的密码:", string(decryPass))*/
	if registry.UseType == 2 {
		scdb.RDB.Get().WithContext(ctx).Model(model.Registry{}).Where("use_type=2").Update("use_type", 0)
	}
	tmpRegistry := model.Registry{}
	res := scdb.RDB.Get().WithContext(ctx).Model(registry).Where("url = ?", registry.Url).First(&tmpRegistry)
	registry.ID = tmpRegistry.ID
	if res.Error == nil {
		if err := scdb.RDB.Get().WithContext(ctx).Updates(&registry).Omit("created_at").Error; err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "InsertToRegistry Updates Registry error%s ", err.Error())
		}
		return
	}
	scdb.RDB.Get().WithContext(ctx).Create(&registry)
}

func (scdb *ScannerDB) GetAuthFromRegistry(ctx context.Context, url string) string {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()

	tmp := model.Registry{}
	res := scdb.RDB.Get().WithContext(ctx).Where("url = ?", url).First(&tmp)
	if res.Error != nil {
		return ""
	}
	key := []byte("talkerss")
	decryPass, err := util.DesDecrypt(tmp.Password, key)
	if err != nil {
		logging.GetLogger().Err(err).Msg("NewChiper Error")
		return ""
	}
	tmpStr := tmp.Username + ":" + string(decryPass)
	authByte := []byte(tmpStr)
	encodeStr := base64.StdEncoding.EncodeToString(authByte)
	authStr := "Basic " + encodeStr
	return authStr
}

func (scdb *ScannerDB) GetScanOneStatus(ctx context.Context, repositoryName string, tag string, digest string, fromURL string) string {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	tmp := model.ImageList{}
	res := scdb.RDB.Get().WithContext(ctx).Where(&model.ImageList{FullRepoName: repositoryName, Tags: tag, Digest: digest}).First(&tmp)
	if res.Error != nil {
		return "not_scan"
	}
	tmpScanImage := model.ScanImage{}
	res = scdb.RDB.Get().WithContext(ctx).Where(&model.ScanImage{ImageID: tmp.ID}).First(&tmpScanImage)
	if res.Error != nil {
		return "not_scan"
	}
	return tmpScanImage.Status
}

func (scdb *ScannerDB) InsertImageList(ctx context.Context, im model.ImageList) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	tmp := model.ImageList{}
	res := scdb.RDB.Get().WithContext(ctx).Where("full_repo_name = ? AND tags = ? AND library = ? AND from_type = ? AND registry_id = ?", im.FullRepoName, im.Tags, im.Library, im.FromType, im.RegistryID).First(&tmp)
	if res.Error != nil {
		err := scdb.RDB.Get().WithContext(ctx).Create(&im).Error
		return im.ID, err
	}
	if tmp.Status < 0 {
		im.Status = 0
	} else {
		im.Status = tmp.Status
	}
	im.OnLineCount = tmp.OnLineCount
	err := scdb.RDB.Get().WithContext(ctx).Model(tmp).Omit("created_at").Updates(&im).Error
	return tmp.ID, err
}

func (scdb *ScannerDB) InsertVirusLayer(ctx context.Context, si model.ScanLayer) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	tmp := model.ScanLayer{}
	res := scdb.RDB.Get().WithContext(ctx).Model(model.ScanLayer{}).Where("layer_digest = ? AND image_id= ?", si.LayerDigest, si.ImageID).First(&tmp)
	if res.Error != nil {
		scdb.RDB.Get().WithContext(ctx).Model(model.ScanLayer{}).Create(&si)
	} else {
		data := map[string]interface{}{
			"malicious_info_json": si.MaliciousInfoJSON,
			"webshell_info_json":  si.WebshellInfoJSON,
		}
		scdb.RDB.Get().Model(model.ScanLayer{}).Where("layer_digest = ? AND image_id= ?", si.LayerDigest, si.ImageID).Omit("created_at").Updates(data)
	}
}

func (scdb *ScannerDB) InsertVirusInfo(ctx context.Context, si model.ScanImage, tableID int64) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	tmpImage := model.ScanImage{ID: tableID}
	err := scdb.RDB.Get().WithContext(ctx).Model(tmpImage).Select("vuln_score", "sensitive_score", "webshell_score", "virus_score").First(&tmpImage).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("InsertVirusInfo Get Scan_image Error:")
		return
	}
	si.RiskScore = tmpImage.SensitiveScore + tmpImage.VulnScore + math.Min(si.WebshellScore+si.VirusScore, model.MaxWebshellAndVirusScore)
	err = scdb.RDB.Get().WithContext(ctx).Model(model.ScanImage{}).Where("id = ?", tableID).Omit("created_at").
		Select("malicious_info_json", "risk_score", "virus_score", "webshell_score", "webshell_info_json").Updates(si).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("InsertVirusInfo Updata scan_image Error:")
		return
	}
}

func (scdb *ScannerDB) QueryMaliciousResult(ctx context.Context, layerDigest string, nowTime time.Time) (model.ScanLayer, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	tmpScanLayer := model.ScanLayer{}
	err := scdb.RDB.Get().WithContext(ctx).Model(&model.ScanLayer{}).Where("layer_digest = ?", layerDigest).First(&tmpScanLayer).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tmpScanLayer, nil
		}
		return tmpScanLayer, err
	}
	oldTime := nowTime.Add(-144 * time.Hour)
	oldUnix := oldTime.Unix()
	layerUnix := tmpScanLayer.UpdatedAt.Unix()
	if oldUnix < layerUnix {
		return model.ScanLayer{}, nil
	}
	return tmpScanLayer, nil
}

func (scdb *ScannerDB) FailInProgressStatus(ctx context.Context) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	scdb.RDB.Get().WithContext(ctx).Model(model.ScanImage{}).Where("status = ? OR status = ?", model.ScanStatusInProgress, model.ScanStatusPending).Update("status", model.ScanStatusFailed)
}

func (scdb *ScannerDB) TickerFixDataBaseError(ctx context.Context) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	scdb.RDB.Get().WithContext(ctx).Model(model.ScanImage{}).Where("updated_at < ? AND status = ?", time.Now().Add(-20*time.Minute).Format("2006-01-02 15:04:05"), model.ScanStatusInProgress).Update("status", model.ScanStatusFailed)
}

func (scdb *ScannerDB) DebugAutoMigrate(ctx context.Context) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	if err := scdb.RDB.Get().WithContext(ctx).AutoMigrate(model.ImageList{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate image_list")
	}
}

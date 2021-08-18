package store

import (
	"context"
	"encoding/base64"
	"math"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScannerDB struct {
	PostgresDB *rdbtools.GormWrapper
}

func NewScannerDB(psqlDB *rdbtools.GormWrapper) *ScannerDB {
	return &ScannerDB{
		PostgresDB: psqlDB,
	}
}

func (scdb *ScannerDB) InsertToScanImage(ctx context.Context, ScanImage *model.ScanImage) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	tmp := model.ScanImage{}
	res := scdb.PostgresDB.Get().WithContext(ctx).Where(&model.ScanImage{ImageId: ScanImage.ImageId}).First(&tmp)
	if res.Error != nil {
		scdb.PostgresDB.Get().WithContext(ctx).Create(ScanImage)
	} else {
		scdb.UpdateToScanImage(ctx, ScanImage, tmp.ID)
	}
}

func (scdb *ScannerDB) UpdateToScanImage(ctx context.Context, ScanImage *model.ScanImage, tableID int64) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	tmpImage := model.ScanImage{ID: tableID}
	err := scdb.PostgresDB.Get().WithContext(ctx).Model(tmpImage).Select("vuln_score", "sensitive_score", "webshell_score", "virus_score").First(&tmpImage).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("UpdateToScanImage Get Scan_image Error:")
		return
	}
	ScanImage.RiskScore = ScanImage.SensitiveScore + ScanImage.VulnScore + math.Min(tmpImage.WebshellScore+tmpImage.VirusScore, 40)
	tmpImage = model.ScanImage{ID: tableID} // 避免一些并发问题（比如病毒扫描此时更新了分数，与数据库中不一样了，model会成为where条件，导致无法更新数据）
	err = scdb.PostgresDB.Get().WithContext(ctx).Model(tmpImage).Omit("virus_score", "webshell_score").Updates(ScanImage).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("UpdateToScanImage Updata Error:")
		return
	}
}

func (scdb *ScannerDB) GetImageID(ctx context.Context, digest string, fullRepoName string) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	var tmp model.ImageList
	res := scdb.PostgresDB.Get().WithContext(ctx).Where("digest = ? and full_repo_name= ?", digest, fullRepoName).First(&tmp)
	if res.Error != nil {
		return -1, nil
	}
	return tmp.ID, nil
}

func (scdb *ScannerDB) InsertToVuln(ctx context.Context, Vuln *model.Vuln, TableID int64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	tmp := model.Vuln{}
	tmpVulnImage := model.VulnImage{}
	scdb.PostgresDB.Get().WithContext(ctx).Where("Name = ?", Vuln.Name).First(&tmp)
	if tmp.Name != "" {
		//	fmt.Println("VulnName is exist : ", tmp.Name)
		tmpVulnImage.VulnName = tmp.Name
		tmpVulnImage.ImageId = TableID
		scdb.InsertToVulnImage(ctx, &tmpVulnImage)
		return nil
	}
	tmpVulnImage.VulnName = Vuln.Name
	tmpVulnImage.ImageId = TableID
	scdb.InsertToVulnImage(ctx, &tmpVulnImage)
	scdb.PostgresDB.Get().WithContext(ctx).Create(Vuln)
	return nil
}

func (scdb *ScannerDB) InsertToVulnImage(ctx context.Context, VulnImage *model.VulnImage) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	tmp := model.VulnImage{}
	scdb.PostgresDB.Get().WithContext(ctx).Where("vuln_name = ? AND image_id= ?", VulnImage.VulnName, VulnImage.ImageId).First(&tmp)
	if tmp.VulnName != "" {
		logging.GetLogger().Info().Str("VulnImage Name is exist : ", tmp.VulnName)
		return
	}
	scdb.PostgresDB.Get().WithContext(ctx).Create(VulnImage)
}

func (scdb *ScannerDB) InsertToScanLayer(ctx context.Context, ScanLayer *model.ScanLayer) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	tmp := model.ScanLayer{}
	res := scdb.PostgresDB.Get().WithContext(ctx).Where("layer_digest = ? AND image_id= ?", ScanLayer.LayerDigest, ScanLayer.ImageId).First(&tmp)
	if res.Error == nil {
		scdb.PostgresDB.Get().WithContext(ctx).Where("layer_digest = ? AND image_id= ?", ScanLayer.LayerDigest, ScanLayer.ImageId).Updates(&ScanLayer)
		return
	}
	scdb.PostgresDB.Get().WithContext(ctx).Create(&ScanLayer)
}

func (scdb *ScannerDB) FindRegistryFromUrl(ctx context.Context, url string) model.Registry {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	tmp := model.Registry{}
	resRegis := model.Registry{}
	tmp.Url = url
	res := scdb.PostgresDB.Get().WithContext(ctx).Model(tmp).First(&resRegis)
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
	res := scdb.PostgresDB.Get().WithContext(ctx).Model(tmp).Last(&resRegis)
	if res.Error != nil {
		return model.Registry{}
	}
	return resRegis
}

func (scdb *ScannerDB) InsertToRegistry(ctx context.Context, Registry *model.Registry) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	// fmt.Println("初始化时加密前的密码:", string(Registry.Password))
	encryPass, err := util.DesEncrypt(Registry.Password, []byte(consts.EncryptPasswordKey))
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("NewCipher Error")
	}
	Registry.Password = encryPass
	/*decryPass := make([]byte, 1024)
	decryPass, err = scdb.DesDecrypt(encryPass, key)
	fmt.Println("初始化时解压后的密码:", string(decryPass))*/
	if Registry.UseType == 2 {
		scdb.PostgresDB.Get().WithContext(ctx).Model(model.Registry{}).Where("use_type=2").Update("use_type", 0)
	}
	tmpRegistry := model.Registry{}
	res := scdb.PostgresDB.Get().WithContext(ctx).Model(Registry).Where("url = ?", Registry.Url).First(&tmpRegistry)
	Registry.ID = tmpRegistry.ID
	if res.Error == nil {
		if err := scdb.PostgresDB.Get().WithContext(ctx).Updates(&Registry).Debug().Error; err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "InsertToRegistry Updates Registry error%s ", err.Error())
		}
		return
	}
	scdb.PostgresDB.Get().WithContext(ctx).Create(&Registry)
}

func (scdb *ScannerDB) GetAuthFromRegistry(ctx context.Context, url string) string {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*2)
	defer cancelFunc()

	tmp := model.Registry{}
	res := scdb.PostgresDB.Get().WithContext(ctx).Where("url = ?", url).First(&tmp)
	if res.Error != nil {
		return ""
	}
	key := []byte("talkerss")
	decryPass, err := util.DesDecrypt(tmp.Password, key)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("NewChiper Error")
		return ""
	}
	tmpStr := tmp.Username + ":" + string(decryPass)
	authByte := []byte(tmpStr)
	encodeStr := base64.StdEncoding.EncodeToString(authByte)
	authStr := "Basic " + encodeStr
	return authStr
}

func (scdb *ScannerDB) GetScanOneStatus(ctx context.Context, repositoryName string, tag string, digest string, fromUrl string) string {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	tmp := model.ImageList{}
	res := scdb.PostgresDB.Get().WithContext(ctx).Where(&model.ImageList{FullRepoName: repositoryName, Tags: tag, Digest: digest}).First(&tmp)
	if res.Error != nil {
		return "not_scan"
	}
	tmpScanImage := model.ScanImage{}
	res = scdb.PostgresDB.Get().WithContext(ctx).Where(&model.ScanImage{ImageId: tmp.ID}).First(&tmpScanImage)
	if res.Error != nil {
		return "not_scan"
	}
	return tmpScanImage.Status
}

func (scdb *ScannerDB) InsertImageList(ctx context.Context, im model.ImageList) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()

	tmp := model.ImageList{}
	res := scdb.PostgresDB.Get().WithContext(ctx).Where("full_repo_name = ? AND tags = ? AND library = ? AND from_type = ?", im.FullRepoName, im.Tags, im.Library, im.FromType).First(&tmp)
	if res.Error != nil {
		err := scdb.PostgresDB.Get().WithContext(ctx).Create(&im).Error
		return im.ID, err
	}
	if tmp.Status < 0 {
		im.Status = 0
	} else {
		im.Status = tmp.Status
	}
	im.OnLineCount = tmp.OnLineCount
	err := scdb.PostgresDB.Get().WithContext(ctx).Model(tmp).Updates(&im).Error
	return tmp.ID, err
}

func (scdb *ScannerDB) InsertVirusLayer(ctx context.Context, si model.ScanLayer) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	tmp := model.ScanLayer{}
	res := scdb.PostgresDB.Get().WithContext(ctx).Model(model.ScanLayer{}).Where("layer_digest = ? AND image_id= ?", si.LayerDigest, si.ImageId).First(&tmp)
	if res.Error != nil {
		scdb.PostgresDB.Get().WithContext(ctx).Model(model.ScanLayer{}).Create(&si)
	} else {
		data := map[string]interface{}{
			"malicious_info_json": si.MaliciousInfoJSON,
			"webshell_info_json":  si.WebshellInfoJSON,
		}
		scdb.PostgresDB.Get().Model(model.ScanLayer{}).Where("layer_digest = ? AND image_id= ?", si.LayerDigest, si.ImageId).Updates(data)
	}
}

func (scdb *ScannerDB) InsertVirusInfo(ctx context.Context, si model.ScanImage, tableID int64) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	tmpImage := model.ScanImage{ID: tableID}
	err := scdb.PostgresDB.Get().WithContext(ctx).Model(tmpImage).Select("vuln_score", "sensitive_score", "webshell_score", "virus_score").First(&tmpImage).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("InsertVirusInfo Get Scan_image Error:")
		return
	}
	si.RiskScore = tmpImage.SensitiveScore + tmpImage.VulnScore + math.Min(si.WebshellScore+si.VirusScore, 40)
	err = scdb.PostgresDB.Get().WithContext(ctx).Model(model.ScanImage{}).Where("id = ?", tableID).
		Select("malicious_info_json", "risk_score", "virus_score", "webshell_score", "webshell_info_json").Updates(si).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("InsertVirusInfo Updata scan_image Error:")
		return
	}
}

func (scdb *ScannerDB) FailInProgressStatus(ctx context.Context) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()

	scdb.PostgresDB.Get().WithContext(ctx).Model(model.ScanImage{}).Where("status = ? OR status = ?", model.ScanStatusInProgress, model.ScanStatusPending).Update("status", model.ScanStatusFailed)
}

func (scdb *ScannerDB) TickerFixDataBaseError(ctx context.Context) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	scdb.PostgresDB.Get().WithContext(ctx).Model(model.ScanImage{}).Where("updated_at < ? AND status = ?", time.Now().Add(-20*time.Minute).Format("2006-01-02 15:04:05"), model.ScanStatusInProgress).Update("status", model.ScanStatusFailed)
}

func (scdb *ScannerDB) DebugAutoMigrate(ctx context.Context) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	if err := scdb.PostgresDB.Get().WithContext(ctx).AutoMigrate(model.ImageList{}); err != nil {
		logging.GetLogger().Err(err).Msg("AutoMigrate tensor_image_list")
	}
}

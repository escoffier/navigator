package store

import (
	"context"
	"encoding/base64"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
)

type ScannerDB struct {
	PostgresDB *gorm.DB
}

func NewScannerDB(psqlDB *gorm.DB) *ScannerDB {
	return &ScannerDB{
		PostgresDB: psqlDB,
	}
}

func (scdb *ScannerDB) InsertToScanImage(ctx context.Context, ScanImage *model.ScanImage) {
	tmp := model.ScanImage{}
	res := scdb.PostgresDB.Where(&model.ScanImage{ImageId: ScanImage.ImageId}).First(&tmp)
	if res.RowsAffected < 1 {
		scdb.PostgresDB.Create(ScanImage)
	} else {
		scdb.UpdateToScanImage(ctx, ScanImage, tmp.ID)
	}
}

func (scdb *ScannerDB) UpdateToScanImage(ctx context.Context, ScanImage *model.ScanImage, tableID int64) {
	tmpImage := model.ScanImage{ID: tableID}
	scdb.PostgresDB.Model(tmpImage).Updates(ScanImage).Debug()
}

func (scdb *ScannerDB) GetImageID(ctx context.Context, digest string, fullRepoName string) (int64, error) {
	var tmp model.ImageList
	res := scdb.PostgresDB.Where("digest = ? and full_repo_name= ?", digest, fullRepoName).First(&tmp)
	if res.RowsAffected < 1 {
		return -1, nil
	}
	return tmp.ID, nil
	/*rows, err := res.Rows()
	fmt.printf("")
	if err != nil {
		return -1, err
	}
	var tmp model.ImageList
	res.ScanRows(rows, &tmp)
	return tmp.ID, nil*/
}

func (scdb *ScannerDB) InsertToVuln(ctx context.Context, Vuln *model.Vuln, TableID int64) error {
	tmp := model.Vuln{}
	tmpVulnImage := model.VulnImage{}
	scdb.PostgresDB.Where("Name = ?", Vuln.Name).First(&tmp)
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
	scdb.PostgresDB.Create(Vuln)
	return nil
}

func (scdb *ScannerDB) InsertToVulnImage(ctx context.Context, VulnImage *model.VulnImage) {
	tmp := model.VulnImage{}
	scdb.PostgresDB.Where("vuln_name = ? AND image_id= ?", VulnImage.VulnName, VulnImage.ImageId).First(&tmp)
	if tmp.VulnName != "" {
		logging.GetLogger().Info().Str("VulnImage Name is exist : ", tmp.VulnName)
		return
	}
	scdb.PostgresDB.Create(VulnImage)
}

func (scdb *ScannerDB) InsertToScanLayer(ctx context.Context, ScanLayer *model.ScanLayer) {
	tmp := model.ScanLayer{}
	res := scdb.PostgresDB.Where("layer_digest = ? AND image_id= ?", ScanLayer.LayerDigest, ScanLayer.ImageId).First(&tmp)
	if res.RowsAffected >= 1 {
		scdb.PostgresDB.Where("layer_digest = ? AND image_id= ?", ScanLayer.LayerDigest, ScanLayer.ImageId).Updates(&ScanLayer)
		return
	}
	scdb.PostgresDB.Create(&ScanLayer)
}

func (scdb *ScannerDB) FindRegistryFromUrl(url string) model.Registry {
	tmp := model.Registry{}
	resRegis := model.Registry{}
	tmp.Url = url
	res := scdb.PostgresDB.Model(tmp).First(&resRegis)
	if res.RowsAffected < 1 {
		return model.Registry{}
	}
	return resRegis
}

func (scdb *ScannerDB) FindRegistryAll() model.Registry {
	tmp := model.Registry{}
	resRegis := model.Registry{}
	res := scdb.PostgresDB.Model(tmp).Last(&resRegis)
	if res.RowsAffected < 1 {
		return model.Registry{}
	}
	return resRegis
}

func (scdb *ScannerDB) InsertToRegistry(ctx context.Context, Registry *model.Registry) {
	// fmt.Println("初始化时加密前的密码:", string(Registry.Password))
	encryPass := make([]byte, 1024)
	encryPass, err := util.DesEncrypt(Registry.Password, []byte(consts.EncryptPasswordKey))
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("NewCipher Error")
	}
	Registry.Password = encryPass
	/*decryPass := make([]byte, 1024)
	decryPass, err = scdb.DesDecrypt(encryPass, key)
	fmt.Println("初始化时解压后的密码:", string(decryPass))*/
	if Registry.UseType == 2 {
		scdb.PostgresDB.Model(model.Registry{}).Where("use_type=2").Update("use_type", 0)
	}
	tmpRegistry := model.Registry{}
	res := scdb.PostgresDB.Model(Registry).Where("url = ?", Registry.Url).First(&tmpRegistry)
	Registry.ID = tmpRegistry.ID
	if res.RowsAffected >= 1 {
		if err := scdb.PostgresDB.Updates(&Registry).Debug().Error; err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "InsertToRegistry Updates Registry error%s ", err.Error())
		}
		return
	}
	scdb.PostgresDB.Create(&Registry)
}

func (scdb *ScannerDB) GetAuthFromRegistry(ctx context.Context, url string) string {
	tmp := model.Registry{}
	res := scdb.PostgresDB.Where("url = ?", url).First(&tmp)
	if res.RowsAffected < 1 {
		return ""
	}
	key := []byte("talkerss")
	decryPass := make([]byte, 1024)
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
	tmp := model.ImageList{}
	res := scdb.PostgresDB.Where(&model.ImageList{FullRepoName: repositoryName, Tags: tag, Digest: digest}).First(&tmp)
	if res.RowsAffected < 1 {
		return "not_scan"
	}
	tmpScanImage := model.ScanImage{}
	res = scdb.PostgresDB.Where(&model.ScanImage{ImageId: tmp.ID}).First(&tmpScanImage)
	if res.RowsAffected < 1 {
		return "not_scan"
	}
	return tmpScanImage.Status
}

func (scdb *ScannerDB) InsertImageList(im model.ImageList) (int64, error) {
	tmp := model.ImageList{}
	res := scdb.PostgresDB.Where("full_repo_name = ? AND tags = ? AND library = ? AND from_type = ?", im.FullRepoName, im.Tags, im.Library, im.FromType).First(&tmp)
	if res.RowsAffected < 1 {
		err := scdb.PostgresDB.Create(&im).Error
		return im.ID, err
	}
	if tmp.Status < 0 {
		im.Status = 0
	} else {
		im.Status = tmp.Status
	}
	im.OnLineCount = tmp.OnLineCount
	err := scdb.PostgresDB.Model(tmp).Updates(&im).Error
	return tmp.ID, err
}

func (scdb *ScannerDB) InsertVirusLayer(si model.ScanLayer) {
	tmp := model.ScanLayer{}
	res := scdb.PostgresDB.Model(model.ScanLayer{}).Where("layer_digest = ? AND image_id= ?", si.LayerDigest, si.ImageId).First(&tmp)
	if res.RowsAffected < 1 {
		scdb.PostgresDB.Model(model.ScanLayer{}).Create(&si)
	} else {
		scdb.PostgresDB.Model(model.ScanLayer{}).Where("layer_digest = ? AND image_id= ?", si.LayerDigest, si.ImageId).Update("malicious_info_json", si.MaliciousInfoJSON)
	}
}

func (scdb *ScannerDB) InsertVirusInfo(si model.ScanImage, tableID int64) {
	scdb.PostgresDB.Model(model.ScanImage{}).Where("id = ?", tableID).Select("malicious_info_json").Update("malicious_info_json", si.MaliciousInfoJSON)
}

func (scdb *ScannerDB) FailInProgressStatus() {
	scdb.PostgresDB.Model(model.ScanImage{}).Where("status = ? OR status = ?", model.ScanStatusInProgress, model.ScanStatusPending).Update("status", model.ScanStatusFailed)
}

func (scdb *ScannerDB) TickerFixDataBaseError() {
	scdb.PostgresDB.Model(model.ScanImage{}).Where("updated_at < ? AND status = ?", time.Now().Add(-20*time.Minute).Format("2006-01-02 15:04:05"), model.ScanStatusInProgress).Update("status", model.ScanStatusFailed)
}

func (scdb *ScannerDB) DebugAutoMigrate() {
	scdb.PostgresDB.AutoMigrate(model.ImageList{})
}

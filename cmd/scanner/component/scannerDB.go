package component

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gorm.io/gorm"
)

type ScannerDB struct {
	postgresDB *gorm.DB
}

func NewScannerDB(psqlDB *gorm.DB) *ScannerDB {
	return &ScannerDB{
		postgresDB: psqlDB,
	}
}

func (scdb *ScannerDB) DesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = scdb.PKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func (scdb *ScannerDB) PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func (scdb *ScannerDB) DesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = scdb.PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

func (scdb *ScannerDB) PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func (scdb *ScannerDB) InsertToScanImage(ctx context.Context, ScanImage *model.ScanImage) {
	tmp := model.ScanImage{}
	res := scdb.postgresDB.Where(&model.ScanImage{ImageId: ScanImage.ImageId}).First(&tmp)
	if res.RowsAffected < 1 {
		scdb.postgresDB.Create(ScanImage)
	} else {
		scdb.UpdateToScanImage(ctx, ScanImage, tmp.ID)
	}
}

func (scdb *ScannerDB) UpdateToScanImage(ctx context.Context, ScanImage *model.ScanImage, tableID int64) {
	tmpImage := model.ScanImage{ID: tableID}
	scdb.postgresDB.Model(tmpImage).Updates(ScanImage)
}

func (scdb *ScannerDB) GetImageID(ctx context.Context, digest string, fullRepoName string) (int64, error) {
	var tmp model.ImageList
	res := scdb.postgresDB.Where("digest = ? and full_repo_name= ?", digest, fullRepoName).First(&tmp)
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
	scdb.postgresDB.Where("Name = ?", Vuln.Name).First(&tmp)
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
	scdb.postgresDB.Create(Vuln)
	return nil
}

func (scdb *ScannerDB) InsertToVulnImage(ctx context.Context, VulnImage *model.VulnImage) {
	tmp := model.VulnImage{}
	scdb.postgresDB.Where("vuln_name = ? AND image_id= ?", VulnImage.VulnName, VulnImage.ImageId).First(&tmp)
	if tmp.VulnName != "" {
		logging.GetLogger().Info().Str("VulnImage Name is exist : ", tmp.VulnName)
		return
	}
	scdb.postgresDB.Create(VulnImage)
}

func (scdb *ScannerDB) InsertToScanLayer(ctx context.Context, ScanLayer *model.ScanLayer) {
	tmp := model.ScanLayer{}
	res := scdb.postgresDB.Where("layer_digest = ? AND image_id= ?", ScanLayer.LayerDigest, ScanLayer.ImageId).First(&tmp)
	if res.RowsAffected >= 1 {
		scdb.postgresDB.Where("layer_digest = ? AND image_id= ?", ScanLayer.LayerDigest, ScanLayer.ImageId).Updates(&ScanLayer)
		return
	}
	scdb.postgresDB.Create(&ScanLayer)
}

func (scdb *ScannerDB) FindRegistryFromUrl(url string) model.Registry {
	tmp := model.Registry{}
	resRegis := model.Registry{}
	tmp.Url = url
	res := scdb.postgresDB.Model(tmp).First(&resRegis)
	if res.RowsAffected < 1 {
		return model.Registry{}
	}
	return resRegis
}

func (scdb *ScannerDB) FindRegistryAll() model.Registry {
	tmp := model.Registry{}
	resRegis := model.Registry{}
	res := scdb.postgresDB.Model(tmp).Last(&resRegis)
	if res.RowsAffected < 1 {
		return model.Registry{}
	}
	return resRegis
}

func (scdb *ScannerDB) InsertToRegistry(ctx context.Context, Registry *model.Registry) {
	key := []byte("talkerss")
	// fmt.Println("初始化时加密前的密码:", string(Registry.Password))
	encryPass := make([]byte, 1024)
	encryPass, err := scdb.DesEncrypt(Registry.Password, key)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("NewCipher Error")
	}
	Registry.Password = encryPass
	/*decryPass := make([]byte, 1024)
	decryPass, err = scdb.DesDecrypt(encryPass, key)
	fmt.Println("初始化时解压后的密码:", string(decryPass))*/
	res := scdb.postgresDB.Where(Registry).First(&model.Registry{})
	if res.RowsAffected >= 1 {
		return
	}
	scdb.postgresDB.Create(Registry)
}

func (scdb *ScannerDB) GetAuthFromRegistry(ctx context.Context, url string) string {
	tmp := model.Registry{}
	res := scdb.postgresDB.Where("url = ?", url).First(&tmp)
	if res.RowsAffected < 1 {
		return ""
	}
	key := []byte("talkerss")
	decryPass := make([]byte, 1024)
	decryPass, err := scdb.DesDecrypt(tmp.Password, key)
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
	res := scdb.postgresDB.Where(&model.ImageList{FullRepoName: repositoryName, Tags: tag, Digest: digest}).First(&tmp)
	if res.RowsAffected < 1 {
		return "not_scan"
	}
	tmpScanImage := model.ScanImage{}
	res = scdb.postgresDB.Where(&model.ScanImage{ImageId: tmp.ID}).First(&tmpScanImage)
	if res.RowsAffected < 1 {
		return "not_scan"
	}
	return tmpScanImage.Status
}

func (scdb *ScannerDB) InsertImageList(im model.ImageList) {
	tmp := model.ImageList{}
	res := scdb.postgresDB.Where("full_repo_name=? AND tags = ? AND registry_id = ?", im.FullRepoName, im.Tags, im.RegistryId).First(&tmp)
	if res.RowsAffected < 1 {
		scdb.postgresDB.Create(&im)
	} else {
		if tmp.Status < 0 {
			im.Status = 0
		} else {
			im.Status = tmp.Status
		}
		im.OnLineCount = tmp.OnLineCount
		scdb.postgresDB.Model(tmp).Updates(&im)
	}
}

func (scdb *ScannerDB) InsertVirusLayer(si model.ScanLayer) {
	tmp := model.ScanLayer{}
	res := scdb.postgresDB.Model(model.ScanLayer{}).Where("layer_digest = ? AND image_id= ?", si.LayerDigest, si.ImageId).First(&tmp)
	if res.RowsAffected < 1 {
		scdb.postgresDB.Model(model.ScanLayer{}).Create(&si)
	} else {
		scdb.postgresDB.Model(model.ScanLayer{}).Where("layer_digest = ? AND image_id= ?", si.LayerDigest, si.ImageId).Update("malicious_info_json", si.MaliciousInfoJSON)
	}
}

func (scdb *ScannerDB) InsertVirusInfo(si model.ScanImage, tableID int64) {
	scdb.postgresDB.Model(model.ScanImage{}).Where("id = ?", tableID).Select("malicious_info_json").Update("malicious_info_json", si.MaliciousInfoJSON)
}

func (scdb *ScannerDB) FailInProgressStatus() {
	scdb.postgresDB.Model(model.ScanImage{}).Where("status = ? OR status = ?", model.ScanStatusInProgress, model.ScanStatusPending).Update("status", model.ScanStatusFailed)
}

func (scdb *ScannerDB) TickerFixDataBaseError() {
	scdb.postgresDB.Model(model.ScanImage{}).Where("updated_at < ? AND status = ?", time.Now().Add(-20*time.Minute).Format("2006-01-02 15:04:05"), model.ScanStatusInProgress).Update("status", model.ScanStatusFailed)
}

func (scdb *ScannerDB) DebugAutoMigrate() {
	scdb.postgresDB.AutoMigrate(model.ImageList{})
}

package dal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
)

func ImageQuestion(postgresDB *gorm.DB, linkObjectId string, questionId int, exist bool, digest string) error {
	qs := model.QuestionInfo{}
	if exist {
		pgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := postgresDB.WithContext(pgCtx).Where("digest = ? and id =? ", digest, questionId).First(&qs).Error
		if err == gorm.ErrRecordNotFound {
			cstZone := time.FixedZone("CST", 8*3600)
			timeStr := time.Now().In(cstZone).Format("2006-01-02 15:04:05")
			q := model.QuestionInfo{ID: questionId, LinkObjectId: linkObjectId, Digest: digest, Time: timeStr}
			err := postgresDB.Create(&q).Error
			if err != nil {
				return err
			}
		}
		if qs.Digest != "" { // 数据表中有数据时，更新关联mongo数据
			cstZone := time.FixedZone("CST", 8*3600)
			timeStr := time.Now().In(cstZone).Format("2006-01-02 15:04:05")
			q := model.QuestionInfo{ID: questionId, LinkObjectId: linkObjectId, Digest: digest, Time: timeStr}
			postgresDB.WithContext(pgCtx).Model(model.QuestionInfo{QID: qs.QID}).Updates(&q)
		}
		if err != nil {
			return err
		}
	} else {
		postgresDB.Where("digest = ? and id =? ", digest, questionId).Delete(&qs)
	}
	return nil
}

func ScanFinish(postgresDB *gorm.DB, digest string) error {

	cstZone := time.FixedZone("CST", 8*3600)
	timeStr := time.Now().In(cstZone).Format("2006-01-02 15:04:05")
	pgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := postgresDB.WithContext(pgCtx).Model(model.ImageList{}).Where("digest = ? ", digest).Where("status = ?", 0).Updates(model.ImageList{CompleteTime: timeStr}).Error

	if err != nil {
		return err
	}

	return nil

}

func GetAllVirusScanStatus(ctx context.Context, scannerURL string) (int, int) {
	type param struct {
		APIVersion string `json:"apiVersion"`
		Data       struct {
			Item struct {
				Doingnum int `json:"doingnum"`
				Waitnum  int `json:"waitnum"`
			} `json:"item"`
		} `json:"data"`
	}
	var p param
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scan/get/allscanStatus", scannerURL), nil)
	if err != nil {
		return 0, 0
	}
	req.Header.Add("Content-Type", "application/json")

	httpClient := http.Client{}
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		logging.GetLogger().Error().Msgf("failed to send get scan all status request to Virus: %+v", err)
		return 0, 0
	}
	defer util.CloseBodyWithLog(resp.Body)
	if resp.StatusCode != http.StatusOK {
		logging.GetLogger().Error().Msgf("Virus return error: %+v", err)
		return 0, 0
	}

	err = json.NewDecoder(resp.Body).Decode(&p)
	if err != nil {
		logging.GetLogger().Error().Msgf("Failed to decode message from Virus: %+v", err)
		return 0, 0
	}
	return p.Data.Item.Doingnum, p.Data.Item.Waitnum
}

func GetAllVirusScanOneStatus(ctx context.Context, scannerURL, digest string) (string, error) {
	type param struct {
		APIVersion string `json:"apiVersion"`
		Data       struct {
			Item struct {
				Status string `json:"status"`
			} `json:"item"`
		} `json:"data"`
	}
	var p param
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scan/get/sha256scanstatus?digest=%s", scannerURL, digest), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")

	httpClient := http.Client{}
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		logging.GetLogger().Error().Msgf("failed to send get scan one status request to Virus: %+v", err)
		return "", err
	}
	defer util.CloseBodyWithLog(resp.Body)
	if resp.StatusCode != http.StatusOK {
		logging.GetLogger().Error().Msgf("Virus return error: %+v", err)
		return "", err
	}

	err = json.NewDecoder(resp.Body).Decode(&p)
	if err != nil {
		logging.GetLogger().Error().Msgf("Failed to decode message from Virus: %+v", err)
		return "", err
	}
	return p.Data.Item.Status, nil
}

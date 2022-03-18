package dal

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/avast/retry-go"
	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
)

type imageListWithVulnResp struct {
	APIVersion string `json:"apiVersion"`
	Data       struct {
		Items []*model.ImageInfo `json:"items"`
	} `json:"data"`
}

func GetImagesWithGivenVuln(ctx context.Context, scannerURL, imageVulnName string) ([]*model.ImageInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/api/v1/vulns/query/%s", scannerURL, imageVulnName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("new reuqest for GetImagesWithGivenVuln error. url: %s", url)
	}

	var imageResp imageListWithVulnResp
	handler := func(resp *http.Response, err error) error {
		if err != nil {
			return apperror.NewConnectionError(http.StatusInternalServerError, fmt.Errorf("failed to send request: %w. url: %s", err, url))
		}

		err = json.NewDecoder(resp.Body).Decode(&imageResp)
		if err != nil {
			return apperror.NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to decode message from Harbor: %w", err))
		}
		return nil
	}
	err = util.HTTPRequest(ctx, http.DefaultClient, req, handler, retry.Attempts(3))
	if err != nil {
		return nil, err
	}
	return imageResp.Data.Items, nil
}
func ImageQuestion(ctx context.Context, postgresDB *gorm.DB, linkObjectId string, questionId int, exist bool, digest string) error {
	qs := model.QuestionInfo{}
	if exist {
		pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
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

func ScanFinish(ctx context.Context, postgresDB *gorm.DB, digest string) error {

	cstZone := time.FixedZone("CST", 8*3600)
	timeStr := time.Now().In(cstZone).Format("2006-01-02 15:04:05")
	pgCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
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

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to send get scan all status request to Virus")
		return 0, 0
	}
	defer util.CloseBodyWithLog(resp.Body)
	if resp.StatusCode != http.StatusOK {
		logging.GetLogger().Error().Msgf("Virus return error: %+v", err)
		return 0, 0
	}

	err = json.NewDecoder(resp.Body).Decode(&p)
	if err != nil {
		logging.GetLogger().Err(err).Msg("Failed to decode message from Virus")
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

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("failed to send get scan one status request to Virus")
		return "", err
	}
	defer util.CloseBodyWithLog(resp.Body)
	if resp.StatusCode != http.StatusOK {
		logging.GetLogger().Error().Msgf("Virus return error: %+v", err)
		return "", err
	}

	err = json.NewDecoder(resp.Body).Decode(&p)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Failed to decode message from Virus")
		return "", err
	}
	return p.Data.Item.Status, nil
}

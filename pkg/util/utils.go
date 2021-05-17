package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/golang/gddo/httputil/header"
	"github.com/rs/zerolog/log"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gorm.io/gorm"
)

func SortOrderToInt(sortOrder string) int {
	if sortOrder == "asc" {
		return 1
	} else if sortOrder == "desc" {
		return -1
	}
	logging.GetLogger().Warn().Str("sortOrder", sortOrder).Msg("Unknown sortOrder string, can be asc/desc.")
	return 1
}

func DecodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	if reflect.ValueOf(dst).Kind() != reflect.Ptr {
		return errors.New("Expected dst to be pointer")
	}

	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			return errors.New("The http header is not application/json")
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&dst)
	if err != nil {
		return err
	}

	if dec.More() {
		return errors.New("Request body must only contain a single JSON object")
	}

	return nil
}

func CloseBodyWithLog(body io.ReadCloser) {
	err := body.Close()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to close body, but ignoring")
	}
}

func AppendIfMissing(s []string, i string) []string {
	for _, ele := range s {
		if ele == i {
			return s
		}
	}
	return append(s, i)
}

func ContainsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func RemoveScoredNotScoredFrom(thing string) string {
	thing = strings.ReplaceAll(thing, " (Not Scored)", "")
	thing = strings.ReplaceAll(thing, " ( Not Scored)", "")
	thing = strings.ReplaceAll(thing, " (Scored)", "")
	return thing
}

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
		if qs.Digest != "" { //数据表中有数据时，更新关联mongo数据
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
	defer CloseBodyWithLog(resp.Body)
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
	defer CloseBodyWithLog(resp.Body)
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

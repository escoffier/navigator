package component

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/avast/retry-go"
	"github.com/go-redis/redis/v8"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type HarborSvc interface {
	GetRedisClient() *redis.Client
	GetTags(ctx context.Context, url string, authorization string, fullRepoName string, digest string) ([]registry.Tag, error)
	AddHarborScanTask(ctx context.Context, scanReq model.ScannerReq, tags []registry.Tag) []int64
	GetScanResult(ctx context.Context, imgID int64) (model.ScanImage, model.ImageList)
}

type Harbor struct {
	dbdal       store.ScannerDalInterface
	RedisClient *redis.Client
	redclair    *RedClairService
}

func (hb *Harbor) decodeUsernamePassword(authorization string) (string, string, error) {
	// scanTask.Authorization == Basic cm9ib3QkdHMt...

	headerSplit := strings.Split(authorization, " ")
	if len(headerSplit) != 2 {
		return "", "", fmt.Errorf("Expected 'Basic ASDF' format, but got different")
	}
	b64Encoded := headerSplit[1]

	decodedHeader, err := base64.StdEncoding.DecodeString(b64Encoded)
	if err != nil {
		return "", "", fmt.Errorf("Couldn't decode auth string: %w", err)
	}

	// decodedHeader == robot$ts-cdffae66-0edd-11eb-91a9-4e1d0aed31d4:eyJhbGciOiJSUzI1...

	usernamePasswordArr := strings.Split(string(decodedHeader), ":")
	if len(usernamePasswordArr) != 2 {
		return "", "", fmt.Errorf("Expected 'username:password' format, but got different")
	}

	username := usernamePasswordArr[0]
	password := usernamePasswordArr[1]

	return username, password, nil
}

func (hb *Harbor) reqHarbor(ctx context.Context, url string, username string, password string, auth string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err.Error()))
	}
	req.SetBasicAuth("admin", "Harbor12345")
	// req.Header.Set("Authorization", auth)
	var resp *http.Response

	err = util.RetryWithBackoff(ctx, func() error {
		var err error
		resp, err = http.DefaultClient.Do(req.WithContext(ctx))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode >= 500 {
			return fmt.Errorf("status code is %d", resp.StatusCode)
		}
		return nil
	}, retry.Attempts(3))

	// defer util.CloseBodyWithLog(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err.Error()))
	}

	return resp.Body, nil
}

func (hb *Harbor) GetTags(ctx context.Context, url string, authorization string, fullRepoName string, digest string) ([]registry.Tag, error) {
	username, password, _ := hb.decodeUsernamePassword(authorization)
	var projectName string
	if strings.Contains(fullRepoName, "/") {
		index := strings.Index(fullRepoName, "/")
		projectName = fullRepoName[0:index]
		fullRepoName = fullRepoName[index+1:]
	}
	fullRepoName = strings.ReplaceAll(fullRepoName, "/", "%252F")
	tagURL := fmt.Sprintf("%s/%s/projects/%s/repositories/%s/artifacts/%s/tags", url, "api/v2.0", projectName, fullRepoName, digest)
	// fmt.Printf("username %s password %s :\n", username, password)
	body, err := hb.reqHarbor(ctx, tagURL, username, password, authorization)
	if err != nil {
		return []registry.Tag{}, err
	}
	defer util.CloseBodyWithLog(body)
	// test, _ := ioutil.ReadAll(body)
	// fmt.Printf("Body Is :%s", string(test))
	// return []registry.Tag{}, err
	var tags []registry.Tag
	err = json.NewDecoder(body).Decode(&tags)
	if err != nil {
		return []registry.Tag{}, err
	}
	return tags, nil
}

func (hb *Harbor) GetScanResult(ctx context.Context, imgID int64) (model.ScanImage, model.ImageList) {
	resScanImage, resImagelist := hb.dbdal.GetScanimageFromImageList(ctx, imgID)
	return resScanImage, resImagelist
}

func (hb *Harbor) AddHarborScanTask(ctx context.Context, scanReq model.ScannerReq, tags []registry.Tag) []int64 {
	imageIds := make([]int64, 0)
	//	for k := range tags {
	img := model.ImageList{
		FullRepoName: scanReq.Repository,
		Digest:       scanReq.Digest,
		// Size:           int(image.Size),
		Library:    scanReq.URL,
		RegistryID: 0,
		// FirstPushTime:  image.Created,
	}
	imgID, err := hb.dbdal.InsertAdapterImageList(ctx, img)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("InserImage Error")
	}
	resTask, _, err := hb.dbdal.GetTaskFromImageList(ctx, imgID, "", scanReq.Authorization)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("GetTaskFromImageList Error")
	}
	imageIds = append(imageIds, imgID)
	hb.redclair.AddScanTask(resTask, consts.ScanTaskComeFromWeb)
	//	}
	return imageIds
}

func (hb *Harbor) GetRedisClient() *redis.Client {
	return hb.RedisClient
}

func NewHarborSrc(dbdal store.ScannerDalInterface, redis *redis.Client, redclairSvc *RedClairService) *Harbor {
	return &Harbor{dbdal: dbdal, RedisClient: redis, redclair: redclairSvc}
}

package image

import (
	"context"
	"errors"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/avast/retry-go"
	"github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/gorm"
)

const (
	loadIntervalSecs = int64((12 * time.Hour) / time.Second)
)

type ImageService struct {
	ImCh                    chan struct{}
	postgresDB              *rdbtools.GormWrapper
	loadMsgCh               chan struct{}
	harborClient            *harbor.HarborRESTClient
	lastImagesLoadTimestamp int64
}

func NewImageService(postgresDB *rdbtools.GormWrapper, harborClient *harbor.HarborRESTClient) *ImageService {

	im := ImageService{
		postgresDB:   postgresDB,
		loadMsgCh:    make(chan struct{}, 1),
		harborClient: harborClient,
	}

	go im.imageWorker()
	select {
	case im.loadMsgCh <- struct{}{}:
	default:
		logging.GetLogger().Error().Msgf("init  image sync signal error")
	}
	return &im
}

func (im *ImageService) loadImagesFromHarbor(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().WithContext(ctx).Errorf(nil, "loadImagesFromHarbor panic:%v, Stack:%s", r, debug.Stack())
			err = errors.New("panic")
		}
	}()

	if im.getLastImagesLoadTimestamp() > 0 && time.Now().Unix()-im.getLastImagesLoadTimestamp() < loadIntervalSecs {
		return nil
	}

	hbCtx, cancel := context.WithTimeout(ctx, time.Second*20)
	defer cancel()

	resp, _, err := im.harborClient.GetHarborProject(hbCtx)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "get harbor project  error")
		return err
	}

	repositories, err := im.harborClient.GetRepositories(hbCtx, resp)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "get repos from harbor error")
		return err
	}

	artifacts, err := im.harborClient.GetAllArtifacts(ctx, repositories)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "get artifacts from harbor error")
		return err
	}

	err = im.addImg(artifacts)
	if err != nil {
		logging.GetLogger().WithContext(ctx).Errorf(err, "Couldn't insert document")
		return err
	}

	// must set the seccess timestamp when all steps are successful
	im.setImagesLoadStamp()

	return nil
}

func (im *ImageService) setImagesLoadStamp() {
	stamp := time.Now().Unix()
	atomic.StoreInt64(&im.lastImagesLoadTimestamp, stamp)
}

func (im *ImageService) getLastImagesLoadTimestamp() int64 {
	return atomic.LoadInt64(&im.lastImagesLoadTimestamp)
}

func (im *ImageService) imageWorker() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("ImageTicker grouting panic: %v, Stack:%s", r, debug.Stack())
		}
	}()

	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-im.loadMsgCh:
			im.loadImagesFromHarbor(context.Background())
		case <-ticker.C:
			im.loadImagesFromHarbor(context.Background())
		}
	}

}

func (im *ImageService) addImg(artifacts model.Artifacts) error {
	pgCtx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	if im.harborClient.GetApiVersionString() == "api" {

		for _, v := range artifacts.Af1 {
			var il model.ImageList
			il.FullRepoName = v.FullRepoName
			il.Tags = v.Name
			il.Digest = v.Digest
			il.OS = v.Os
			il.Size = v.Size
			il.Library = im.harborClient.GetAddressString()
			cstZone := time.FixedZone("CST", 8*3600)
			timeStr := v.PushTime.In(cstZone).Format("2006-01-02 15:04:05")
			il.OnLineCount = 0
			il.PushTime = timeStr
			il.CreateTime = time.Now().In(cstZone).Format("2006-01-02 15:04:05")
			il.Status = 0
			im.postgresDB.Get().Transaction(func(tx *gorm.DB) error {
				/*
					if the image has existed but with the status -1, we update all the fields and also the status to 0.
					if the image hasn't existed, insert it.
				*/
				var image model.ImageList
				fErr := tx.WithContext(pgCtx).Where("digest = ? AND full_repo_name = ? AND tags = ? AND library = ?", v.Digest, v.FullRepoName, v.Name, il.Library).First(&image).Error
				if fErr != nil {
					err := tx.WithContext(pgCtx).Create(&il).Error
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Couldn't insert postgres")
						return err
					}
				} else if image.Status == -1 {
					err := tx.WithContext(pgCtx).Where("id = ?", image.ID).Updates(il).Error
					if err != nil {
						return err
					}
					err = tx.WithContext(pgCtx).Where("id = ?", image.ID).Update("status", 0).Error
					return err
				}
				return nil
			})

		}
	} else {
		for _, v := range artifacts.Af2 {
			var il model.ImageList
			il.FullRepoName = v.FullRepoName
			split := false
			for _, t := range v.Tags {
				if split == true {
					il.Tags = il.Tags + ";" + t.Name
				} else {
					il.Tags = il.Tags + t.Name
					split = true
				}
			}

			cstZone := time.FixedZone("CST", 8*3600)
			timeStr := v.PushTime.In(cstZone).Format("2006-01-02 15:04:05")
			il.CreateTime = time.Now().In(cstZone).Format("2006-01-02 15:04:05")
			il.PushTime = timeStr
			il.Digest = v.Digest
			il.OS = v.ExtraAttrs.Os
			il.Size = v.Size
			il.Library = im.harborClient.GetAddressString()
			il.Status = 0
			im.postgresDB.Get().Transaction(func(tx *gorm.DB) error {
				/*
					if the image has existed but with the status -1, we update all the fields and also the status to 0.
					if the image hasn't existed, insert it.
				*/
				var image model.ImageList
				fErr := tx.WithContext(pgCtx).Where("digest = ? AND full_repo_name = ? AND tags = ?", v.Digest, v.FullRepoName, il.Tags).First(&image).Error
				if fErr != nil {
					err := tx.WithContext(pgCtx).Create(&il).Error
					if err != nil {
						logging.GetLogger().Error().Err(err).Msg("Couldn't insert postgres")
						return err
					}
				} else if image.Status == -1 {
					err := tx.WithContext(pgCtx).Where("id = ?", image.ID).Updates(il).Error
					if err != nil {
						return err
					}
					err = tx.WithContext(pgCtx).Where("id = ?", image.ID).Update("status", 0).Error
					return err
				}
				return nil
			})

		}
	}

	return nil
}

//postgresDB
func (im *ImageService) CheckImgExistence(ctx context.Context, tx *gorm.DB, fullRepoName, digest string) bool {
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	imageList := model.ImageList{}
	err := tx.WithContext(pgCtx).Where("full_repo_name = ? AND digest = ? AND status = ?", fullRepoName, digest, 0).First(&imageList).Error
	if err != nil {
		return false
	}

	return true
}

// FIXME still uses mongoDB imageLists
func (im *ImageService) ImageScanOnline(mongodb *mongotools.DatabaseWrapper, harborClient *harbor.HarborRESTClient, cache *cache.Cache) {
	cache.Set(model.SCANSTAUTS, struct{}{}, -1)
	defer cache.Delete(model.SCANSTAUTS)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()

	digest := make([]string, 0)
	filter := bson.M{}

	asFilter := bson.M{
		"isDeleted": false,
	}
	findOptions := options.Find().SetMaxTime(time.Second * 10)
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	cursor, err := mongodb.Get().Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, asFilter, findOptions)
	if err == nil {
		defer func() {
			if err := cursor.Close(ctx); err != nil {
				logging.GetLogger().Error().Err(err).Msg("When closing cursor, but ignoring.")
			}
		}()
		for cursor.Next(ctx) {
			var container model.AssetContainer
			err := cursor.Decode(&container)
			if err == nil {
				digest = append(digest, container.Digest)
			}
		}
	}

	filter = bson.M{"digest": bson.M{"$in": digest}}

	opt := options.Find()
	opt.SetMaxTime(time.Second * 2)

	cur, err := mongodb.Get().Collection(model.ImageListCollection.String()).Find(ctx, filter, opt)
	if err != nil {
		logging.GetLogger().Error().Msgf("couldn't find document: %+v", err)
		return
	}

	ImageListSlice := make([]model.ImageList, 0)
	for cur.Next(ctx) {
		var il model.ImageList
		err := cur.Decode(&il)
		if err != nil {
			logging.GetLogger().Error().Msgf("couldn't decode document: %+v", err)
			return
		}
		ImageListSlice = append(ImageListSlice, il)
	}
	for _, v := range ImageListSlice {
		projectNameRepoName := strings.SplitN(v.FullRepoName, "/", 2)
		projectName := projectNameRepoName[0]
		repoName := projectNameRepoName[1]
		frepoName := strings.Replace(repoName, "/", "%252F", -1)
		tag := strings.SplitN(v.Tags, ";", 2)
		err := retry.Do(
			func() error {
				err = harborClient.ScanOne(ctx, projectName, frepoName, tag[0])
				if err != nil {
					logging.GetLogger().Error().Msgf("retry->projectName:%+v ,frepoName:%+v,tags:%+v,Failed to trigger  scan one in Harbor: %+v,", projectName, frepoName, tag, err)
					return err
				}
				return nil
			}, retry.Attempts(5))
		if err != nil {
			logging.GetLogger().Error().Msgf("projectName:%+v ,frepoName:%+v,tags:%+v,Failed to trigger  scan one in Harbor: %+v,", projectName, frepoName, tag, err)
			time.Sleep(time.Millisecond * 200)
		}
		time.Sleep(time.Millisecond * 200)
	}

}

func (im *ImageService) ScanImageCheck(ctx context.Context, fullRepoName, digest string) {
	var ok bool
	im.postgresDB.Get().Transaction(func(tx *gorm.DB) error {

		ok = im.CheckImgExistence(ctx, tx, fullRepoName, digest)
		return nil
	})
	if !ok {
		af, err := im.harborClient.GetOneArtifacts(fullRepoName)
		if err != nil {
			im.addImg(af)
		}
		select {
		case im.loadMsgCh <- struct{}{}:
		default:
			logging.GetLogger().Error().Msgf("send  image sync signal error")
		}
	}
}

func (im *ImageService) GetImageScanStatus(ctx context.Context, harborClient *harbor.HarborRESTClient, fullRepoName, tag, digest, scannerURL string) string {

	projectNameRepoName := strings.SplitN(fullRepoName, "/", 2)
	projectName := projectNameRepoName[0]
	repoName := projectNameRepoName[1]
	frepoName := strings.Replace(repoName, "/", "%252F", -1)

	tags := strings.SplitN(tag, ";", 2)

	_, status, err := harborClient.ScanOneStatus(ctx, projectName, frepoName, tags[0], digest)
	if err != nil {
		logging.GetLogger().Error().Msgf("get harbor image scan status error:%+v", err)
		return model.JobFinished
	}
	virusStatus, err := util.GetAllVirusScanOneStatus(ctx, scannerURL, digest)
	if err != nil || virusStatus == "" {
		return status
	}

	if virusStatus == model.VirusStatusDoing || virusStatus == model.VirusStatusWait {
		return model.JobRunning
	}
	return status
}

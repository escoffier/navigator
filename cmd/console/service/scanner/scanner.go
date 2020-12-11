package scanner

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	rcache "gitlab.com/piccolo_su/vegeta/pkg/cache"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ScannerService struct {
	mongodb                 *mongo.Database
	imageVulnerabilityCache *rcache.ImageVulnerabilityCache
	scannedImagesCache      *rcache.ScannedImagesCache
}

func NewScannerService(ctx context.Context, redisClient *redis.Client, mongodb *mongo.Database, harborClient *harbor.HarborRESTClient) *ScannerService {
	return &ScannerService{
		mongodb:                 mongodb,
		imageVulnerabilityCache: rcache.NewImageVulnerabilityCache(ctx, mongodb, redisClient),
		scannedImagesCache:      rcache.NewScannedImagesCache(ctx, mongodb, redisClient, harborClient),
	}
}

func (s *ScannerService) GetScannedImages(ctx context.Context, maxImageAgeInHours int, offset int64, limit int64, sortBy string, sortOrder string) ([]model.ImageScanSummaryResult, int64, error) {
	scanTaskIds, docNum, err := s.scannedImagesCache.GetItems(ctx, maxImageAgeInHours, offset, limit, sortBy, sortOrder)
	if err != nil {
		return nil, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Failed to get results from cache: %w", err))
	}

	items := make([]model.ImageScanSummaryResult, len(scanTaskIds))
	ids := make([]primitive.ObjectID, len(scanTaskIds))
	for i := range scanTaskIds {
		ids[i] = scanTaskIds[i].ID
	}

	filter := bson.D{{"_id", bson.D{{"$in", ids}}}}
	opts := options.Find()
	opts.SetSort(bson.D{{sortBy, util.SortOrderToInt(sortOrder)}})
	opts.SetMaxTime(time.Second * 10)

	coll := s.mongodb.Collection(model.ScanTasksCollection.String())
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	cur, err := coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find documents: %w", err))
	}
	defer cur.Close(mongoCtx)
	var scanTaskNo int = 0
	for cur.Next(mongoCtx) {
		var scanTask model.ScanTask
		err := cur.Decode(&scanTask)
		if err != nil {
			return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}

		report := scanTask.ScanReport.Vulns

		topVulnsNum := len(report.Vulnerabilities)
		if len(report.Vulnerabilities) >= 5 {
			topVulnsNum = 5
		}

		for j := range report.Sensitives {
			if lang.Language(ctx) == lang.LanguageZH {
				description := report.Sensitives[j].DescriptionZh
				report.Sensitives[j].Description = description
			} else {
				description := report.Sensitives[j].DescriptionEn
				report.Sensitives[j].Description = description
			}
		}

		imageScanResult := model.ImageScanSummaryResult{
			TopVulns:          report.Vulnerabilities[:topVulnsNum],
			SensitiveFiles:    report.Sensitives,
			Repository:        report.Repository,
			Tag:               report.Tag,
			Digest:            report.Digest,
			TaskID:            scanTask.ID,
			StartedAt:         scanTask.StartedAt,
			FinishedAt:        scanTask.FinishedAt,
			OverallSeverity:   scanTask.ScanReport.OverallSeverity,
			SeverityHistogram: scanTask.ScanReport.SeverityHistogram,
		}

		items[scanTaskNo] = imageScanResult

		scanTaskNo++
	}
	err = cur.Err()
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Mongo cursor error: %w", err))
	}

	return items, docNum, nil
}

func (s *ScannerService) GetImageVulnerabilities(ctx context.Context, riskFilter string, offset int64, limit int64, sortOrder string) ([]model.VulnerabilityInImages, int64, error) {
	vulnerabilityInImagesIds, docNum, err := s.imageVulnerabilityCache.GetItems(ctx, riskFilter, offset, limit, sortOrder)
	if err != nil {
		return nil, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Failed to get results from cache: %w", err))
	}

	items := make([]model.VulnerabilityInImages, len(vulnerabilityInImagesIds))

	ids := make([]primitive.ObjectID, len(vulnerabilityInImagesIds))
	for i := range vulnerabilityInImagesIds {
		ids[i] = vulnerabilityInImagesIds[i].ID
	}

	filter := bson.D{{"_id", bson.D{{"$in", ids}}}}
	opts := options.Find()
	opts.SetMaxTime(time.Second * 10)
	opts.SetSort(bson.D{{"createdAt", util.SortOrderToInt("desc")}})

	coll := s.mongodb.Collection(model.VulnerabilitiesInImagesCollection.String())
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	cur, err := coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find documents: %w", err))
	}
	defer cur.Close(mongoCtx)
	var vulnerabilityInImagesNo int = 0
	for cur.Next(mongoCtx) {
		var vulnerabilityInImages model.VulnerabilityInImages
		err := cur.Decode(&vulnerabilityInImages)
		if err != nil {
			return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}

		items[vulnerabilityInImagesNo] = vulnerabilityInImages
		vulnerabilityInImagesNo++
	}
	err = cur.Err()
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Mongo cursor error: %w", err))
	}

	redclair.SortVulnerabilitiesInImagesBySeverityAndStuff(items, sortOrder == "asc")

	return items, docNum, nil
}

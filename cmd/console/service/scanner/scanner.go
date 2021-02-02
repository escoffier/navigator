package scanner

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"net/http"
	"strings"
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

const SCAN_SERVICE = "service"

type ScannerService struct {
	mongodb                 *mongo.Database
	imageVulnerabilityCache *rcache.ImageVulnerabilityCache
	scannedImagesCache      *rcache.ScannedImagesCache
	harborClient            *harbor.HarborRESTClient
}

func NewScannerService(ctx context.Context, redisClient *redis.Client, mongodb *mongo.Database, harborClient *harbor.HarborRESTClient) *ScannerService {
	return &ScannerService{
		mongodb:                 mongodb,
		imageVulnerabilityCache: rcache.NewImageVulnerabilityCache(ctx, mongodb, redisClient),
		scannedImagesCache:      rcache.NewScannedImagesCache(ctx, mongodb, redisClient, harborClient),
		harborClient:            harborClient,
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
			HarborURL:         scanTask.HarborURL,
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

func (s *ScannerService) GetServiceScannedImages(ctx context.Context, offset int64, limit int64, sortBy, namespace, svcname string, sortOrder string) ([]model.ImageScanSummaryResult, int64, error) {

	shaSlice, err := assets.GetServiceSha256Val(s.mongodb, namespace, svcname)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get podName from service info : %w", err))
	}

	items := make([]model.ImageScanSummaryResult, 0)

	filter := bson.M{"digest": bson.D{{"$in", shaSlice}}, "scan_report.vulnerability.repository": bson.D{{"$ne", ""}, {"$exists", true}}}
	opts := options.Find()
	opts.SetSort(bson.D{{sortBy, util.SortOrderToInt(sortOrder)}})
	opts.SetMaxTime(time.Second * 10)
	opts.SetSkip(offset)
	opts.SetLimit(limit)

	copt := options.Count()
	copt.SetMaxTime(time.Second * 10)

	coll := s.mongodb.Collection(model.ScanTasksCollection.String())
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	itemCount, err := coll.CountDocuments(mongoCtx, filter, copt)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find count  documents: %w", err))
	}
	cur, err := coll.Find(mongoCtx, filter, opts)

	defer cur.Close(mongoCtx)
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
			HarborURL:         scanTask.HarborURL,
			Tag:               report.Tag,
			Digest:            report.Digest,
			TaskID:            scanTask.ID,
			StartedAt:         scanTask.StartedAt,
			FinishedAt:        scanTask.FinishedAt,
			OverallSeverity:   scanTask.ScanReport.OverallSeverity,
			SeverityHistogram: scanTask.ScanReport.SeverityHistogram,
		}
		items = append(items, imageScanResult)
	}
	err = cur.Err()
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("mongo cursor error: %w", err))
	}

	return items, itemCount, nil
}

//service scan
func (s *ScannerService) SetServiceScanImages(ctx context.Context, namespace, resourcesName, selecter string) error {
	var imageSlice []string
	var err error

	if selecter == SCAN_SERVICE {
		imageSlice, err = assets.GetServiceImages(s.mongodb, namespace, resourcesName)
		if err != nil {
			return NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("couldn't get imageSlice from service info : %w", err))
		}
	}

	imageSet := make(map[string]struct{})
	for _, v := range imageSlice {
		imageSet[v] = struct{}{}
	}

	for k, _ := range imageSet {
		projectName, repositoryName, tag := s.getImageInfo(k)
		if projectName == "" || repositoryName == "" || tag == "" {
			continue
		} else {
			err := s.harborClient.ScanOne(ctx, projectName, repositoryName, tag)
			if err != nil {
				logging.GetLogger().Info().Msgf("service  scan image  error:%+v", err)
				return err
			}
		}
	}

	return nil
}

func (s *ScannerService) getImageInfo(image string) (projectName, repositoryName, tag string) {

	subStr := "/"
	idx := strings.Index(image, subStr)
	idx1 := strings.Index(image[idx+1:], subStr)
	if idx+1+idx1 > len(image) || idx == -1 || idx1 == -1 {
		projectName = ""
	} else {
		projectName = image[idx+1 : idx+1+idx1]
	}
	lastIndex := strings.LastIndex(image, ":")
	if lastIndex == -1 || lastIndex > len(image) {
		repositoryName = ""
		tag = ""
	} else {
		repositoryName = image[idx+2+idx1 : lastIndex]
		tag = image[lastIndex+1:]
	}
	return projectName, repositoryName, tag

}

//service scan
func (s *ScannerService) GetServiceScanImagesStatus(ctx context.Context, namespace, svcname, selecter string) (harbor.ScanAllStatus, error) {
	var status harbor.ScanAllStatus
	var imageSlice []string
	var err error
	if selecter == SCAN_SERVICE {
		imageSlice, err = assets.GetServiceImages(s.mongodb, namespace, svcname)
		if err != nil {
			return status, NewMongoError(http.StatusInternalServerError,
				fmt.Errorf("couldn't get imageSlice from service info : %w", err))
		}

	}

	imageMap := make(map[string]struct{})
	for _, v := range imageSlice {
		imageMap[v] = struct{}{}
	}

	for k, _ := range imageMap {

		projectName, repositoryName, tag := s.getImageInfo(k)
		if projectName == "" || repositoryName == "" || tag == "" {
			continue
		} else {
			status.Total += 1
			imageStatus, err := s.harborClient.ScanOneStatus(ctx, projectName, repositoryName, tag)
			if err != nil {
				logging.GetLogger().Info().Msgf("scan one  error :%+v", err)
			}
			if imageStatus == "Running" {
				status.IsOngoing = true
				status.Metrics.Running = +1
			} else if imageStatus == "Success" {
				status.Completed = +1
				status.Metrics.Success = +1
				if status.Total == status.Completed+status.Metrics.Error {
					status.IsOngoing = false
				}
			} else if imageStatus == "Error" {
				status.Metrics.Error = +1
				if status.Total == status.Completed+status.Metrics.Error {
					status.IsOngoing = false
				}
			} else if imageStatus == "Pending" {
				status.IsOngoing = true
				status.Metrics.Pending = +1
			} else if imageStatus == "" {
				status.Metrics.Error = +1
				if status.Total == status.Completed+status.Metrics.Error {
					status.IsOngoing = false
				}
			}
		}
	}

	return status, nil
}

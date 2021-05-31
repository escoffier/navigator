package scanner

import (
	"context"
	"fmt"
	"gorm.io/gorm"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/image"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const SCAN_SERVICE = "service"

const OverviewOnlineSQL = `SELECT qt.id, COUNT(qt.id) 
FROM tensor_image_list il LEFT JOIN tensor_question qt ON il.digest = qt.digest 
WHERE il.status = 0 AND il.on_line_count > 0  and qt.id >=0 GROUP BY qt.id;
`
const OverviewTotalSQL = `SELECT qt.id, COUNT(qt.id) 
FROM tensor_image_list il LEFT JOIN tensor_question qt ON il.digest = qt.digest 
WHERE il.status = 0  and qt.id >=0 GROUP BY qt.id;
`

type ScannerService struct {
	postgresDB   *rdbtools.GormWrapper
	mongodb      *mongotools.DatabaseWrapper
	harborClient *harbor.HarborRESTClient
}

func NewScannerService(ctx context.Context, redisClient *redis.Client, postgresDB *rdbtools.GormWrapper, mongodb *mongotools.DatabaseWrapper, harborClient *harbor.HarborRESTClient) *ScannerService {
	return &ScannerService{
		postgresDB:   postgresDB,
		mongodb:      mongodb,
		harborClient: harborClient,
	}
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

	coll := s.mongodb.Get().Collection(model.ScanTasksCollection.String())
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
			_, imageStatus, err := s.harborClient.ScanOneStatus(ctx, projectName, repositoryName, tag, "")
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

func (s *ScannerService) GetImageList(ctx context.Context, offset int64, limit int64, search, online, kind string) ([]model.ImageList, int64, error) {

	pctx, postgresDBCancel := context.WithTimeout(ctx, 2*time.Second)
	defer postgresDBCancel()
	db := s.postgresDB.Get().WithContext(pctx)
	var subQuery1 *gorm.DB

	if kind != "" {
		kindSlie := strings.Split(kind, ",")
		if len(kindSlie) != 0 {
			subQuery1 = s.postgresDB.Get().WithContext(pctx).Model(&model.QuestionInfo{}).Select("digest").Where("ID in (?)", kindSlie)
			db = db.Where("digest in (?)", subQuery1)
		}
	}

	if search != "" {
		idx := strings.LastIndex(search, ":")
		if idx != -1 {
			flike := "%" + search[:idx] + "%"
			tlike := "%" + search[idx+1:] + "%"
			db = db.Where(" full_repo_name like ? and tags like ?   ", flike, tlike)
		} else {
			flike := "%" + search + "%"
			db = db.Where(" full_repo_name like ? ", flike)
		}
	}

	if online == "true" {
		db = db.Where(" on_line_count > 0 ")
	}

	db = db.Where("status = ?", 0)

	var im []model.ImageList
	var count int64

	db = db.Model(&model.ImageList{})
	db.Count(&count)

	err := db.Limit(int(limit)).Offset(int(offset)).Where("status=?", 0).Order("on_line_count desc").Find(&im).Error

	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find image list  info: %w", err))
		return nil, 0, err
	}
	for i := range im {
		var qs []model.QuestionInfo
		qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
		defer qcancel()
		err = s.postgresDB.Get().WithContext(qctx).Where("digest = ?", im[i].Digest).Find(&qs).Error
		if err == nil {
			im[i].Questions = append(im[i].Questions, qs...)
		}
	}

	return im, count, nil

}

func (s *ScannerService) GetImageOverView(ctx context.Context) (image.OverView, error) {
	digest := make(map[string]struct{}, 0)
	var overView image.OverView

	pctx, postgresDBCancel := context.WithTimeout(ctx, 5*time.Second)
	defer postgresDBCancel()
	var cnt int64
	s.postgresDB.Get().WithContext(pctx).Model(&model.ImageList{}).Where("on_line_count >0").Where("status=?", 0).Count(&cnt)

	overView.OnlineTotal = int(cnt)
	var count int64
	err := s.postgresDB.Get().WithContext(pctx).Model(&model.ImageList{}).Where("status=?", 0).Count(&count).Error
	overView.ImageTotal = int(count)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find image list  info: %w", err))
		return overView, err
	}

	type Result struct {
		Id    int `json:"id"`
		Count int `json:"count"`
	}

	var result []Result
	//
	s.postgresDB.Get().WithContext(pctx).Raw(OverviewTotalSQL).Scan(&result)
	for i := range result {
		if result[i].Id == model.QUESTION_VULN {
			overView.Sum.VULN = result[i].Count
		} else if result[i].Id == model.QUESTION_VIRUS {
			overView.Sum.VIRUS = result[i].Count
		} else if result[i].Id == model.QUESTION_SENSITIVE {
			overView.Sum.SENSITIVE = result[i].Count
		} else if result[i].Id == model.QUESTION_NETWORK_VULN {
			overView.Sum.NETWORK_VULN = result[i].Count
		}
	}
	//online
	var digestSli []string
	for k, _ := range digest {
		digestSli = append(digestSli, k)
	}
	var onlineResult []Result

	s.postgresDB.Get().WithContext(pctx).Raw(OverviewOnlineSQL).Scan(&onlineResult)

	for i := range onlineResult {
		if onlineResult[i].Id == model.QUESTION_VULN {
			overView.Online.VULN = onlineResult[i].Count
		} else if onlineResult[i].Id == model.QUESTION_VIRUS {
			overView.Online.VIRUS = onlineResult[i].Count
		} else if onlineResult[i].Id == model.QUESTION_SENSITIVE {
			overView.Online.SENSITIVE = onlineResult[i].Count
		} else if onlineResult[i].Id == model.QUESTION_NETWORK_VULN {
			overView.Online.NETWORK_VULN = onlineResult[i].Count
		}
	}
	return overView, nil

}

func (s *ScannerService) GetImageDetail(ctx context.Context, digest, fullRepoName string) (model.ImageList, error) {
	var scanTask model.ScanTask
	var il model.ImageList
	var qs []model.QuestionInfo
	mongoCtx, mongoCancel := context.WithTimeout(ctx, 5*time.Second)
	defer mongoCancel()

	opt := options.FindOne()
	opt.SetMaxTime(time.Second * 2)
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := s.postgresDB.Get().WithContext(pctx).Where("digest = ? AND full_repo_name = ? AND status = ?", digest, fullRepoName, 0).First(&il).Error

	if err != nil {
		return il, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find image imfo: %w", err))
	}

	//get questuon

	//get question info
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	err = s.postgresDB.Get().WithContext(qctx).Where("digest = ?", digest).Find(&qs).Error
	if err == nil {
		il.Questions = append(il.Questions, qs...)
	}
	for _, v := range qs {

		if v.ID == model.QUESTION_VULN {
			id, _ := primitive.ObjectIDFromHex(v.LinkObjectId)
			vuln_filter := bson.M{"_id": id}
			opts := options.FindOne()
			opts.SetMaxTime(time.Second * 10)
			coll := s.mongodb.Get().Collection(model.ScanTasksCollection.String())
			err = coll.FindOne(mongoCtx, vuln_filter, opts).Decode(&scanTask)
			if err == nil {
				report := scanTask.ScanReport.Vulns

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
					TopVulns:          report.Vulnerabilities,
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
				il.ImageScanVuln = imageScanResult
			}
			continue
		} else if v.ID == model.QUESTION_SENSITIVE {
			id, _ := primitive.ObjectIDFromHex(v.LinkObjectId)
			vuln_filter := bson.M{"_id": id}
			opts := options.FindOne()
			opts.SetMaxTime(time.Second * 10)

			coll := s.mongodb.Get().Collection(model.ScanTasksCollection.String())

			err = coll.FindOne(mongoCtx, vuln_filter, opts).Decode(&scanTask)
			if err == nil {
				report := scanTask.ScanReport.Vulns

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
					TopVulns:          report.Vulnerabilities,
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
				il.ImageScanVuln = imageScanResult
			}
			continue
		} else if v.ID == model.QUESTION_VIRUS {
			id, _ := primitive.ObjectIDFromHex(v.LinkObjectId)
			vopt := options.FindOne()
			vopt.SetMaxTime(time.Second * 10)
			var virusScan model.VirusScanTask

			virus_filter := bson.M{"_id": id}
			err = s.mongodb.Get().Collection(model.VirusScanTaskCollection.String()).FindOne(ctx, virus_filter, vopt).Decode(&virusScan)
			if err == nil {
				for _, v := range virusScan.ScanReport.Virus.Virus {
					il.ImageScanVirus = append(il.ImageScanVirus, model.VirusFileInfo{Filename: v.FileName, Filepath: v.FilePath, Virusname: v.VirusName})
				}
			}
			continue
		}
	}

	findOptions := options.Find().SetMaxTime(time.Second * 10)
	filter := bson.M{"digest": digest, "isDeleted": false}
	cursor, err := s.mongodb.Get().Collection(model.AssetsContainersCollection.String()).Find(mongoCtx, filter, findOptions)
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
				il.Container = append(il.Container, container)
			}
		}
	} else if err != mongo.ErrNoDocuments {
		logging.GetLogger().Error().Msgf("find assets containers error:%+v", err)
	}

	return il, nil

}

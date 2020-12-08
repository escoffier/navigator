package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	imageVulnerabilitiesKey = "ImageVulnerabilities"
)

type ImageVulnerabilityCache struct {
	ctx         context.Context
	ch          *util.CacheHelper
	mongodb     *mongo.Database
	redisClient *redis.Client
}

func NewImageVulnerabilityCache(
	ctx context.Context,
	mongodb *mongo.Database,
	redisClient *redis.Client,
) *ImageVulnerabilityCache {

	c := &ImageVulnerabilityCache{
		ctx:         ctx,
		mongodb:     mongodb,
		redisClient: redisClient,
	}
	c.ch = util.NewCacheHelper(
		ctx,
		"ImageVulnerability",
		redisClient,
		c.getScanTaskNewestEntryTimestamp,
		util.FinishedAtKey,
		false,
	)
	go c.bgSync()
	return c
}

const (
	BySeverityKey           = "BySeverity"
	MedToCriticalKey        = "MedToCritical"
	NetWorkBasedKey         = "NetWorkBased"
	ScanTypeBySeverity      = 1
	ScanTypeByMedToCritical = 2
	ScanTypeNetWorkBased    = 3
)

type imageVulnerabilitiesMongoResult struct {
	listItemsBySeverity    *[]model.ScanReportListItem
	listItemsMedToCritical *[]model.ScanReportListItem
	listItemsNetWorkBased  *[]model.ScanReportListItem
	FinishedAt             int64
}

func (c *ImageVulnerabilityCache) getScanTaskNewestEntryTimestamp() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, util.MongoTimeout)
	defer cancel()
	filter := bson.M{
		"$and": []bson.M{
			{"stale": false},
			{"status": model.ScanStatusSucceeded},
		},
	}

	findOptions := options.FindOne()
	findOptions.SetSort(bson.D{{"finishedAt", -1}})

	singleResult := c.mongodb.Collection(model.ScanTasksCollection.String()).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		if singleResult.Err() == mongo.ErrNoDocuments {
			return -1, nil
		}
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("singleResult error: %w", singleResult.Err()))
	}

	var scanTask model.ScanTask
	err := singleResult.Decode(&scanTask)
	if err != nil {
		return -1, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode scan task: %w ", err))
	}
	return scanTask.FinishedAt, nil
}

func (c *ImageVulnerabilityCache) checkVersion(ctx context.Context, mongodb *mongo.Database, redisClient *redis.Client) (bool, error) {

	mongoFinishedAt, err := c.getScanTaskNewestEntryTimestamp()
	if err != nil {
		return false, NewAnError(http.StatusInternalServerError, fmt.Errorf("getMongoMaxFinishedAt error: %w ", err))
	}
	redisFinishedAt, err := c.ch.GetCachedTimestamp()
	if err != nil {
		return false, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("getRedisMaxFinishedAt error: %w ", err))
	}
	if mongoFinishedAt != -1 && redisFinishedAt != -1 && mongoFinishedAt == redisFinishedAt {
		return true, nil
	}
	return false, nil
}

func (c *ImageVulnerabilityCache) getMongoData(ctx context.Context) (*imageVulnerabilitiesMongoResult, error) {
	ctx, cancel := context.WithTimeout(ctx, util.MongoTimeout)
	defer cancel()
	//By Severity
	//Med to Critical
	//Network based

	filter := bson.M{
		"$and": []bson.M{
			{"stale": false},
			{"status": model.ScanStatusSucceeded},
		},
	}
	cursor, err := c.mongodb.Collection(model.ScanTasksCollection.String()).Find(ctx, filter)

	if err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't find document:%w ", err))
	}
	defer cursor.Close(ctx)

	type vulnInfoEx struct {
		// Helper struct that creates one to one mapping between vulnerability and affected image.
		model.VulnerabilityInfo
		AffectedRepository string
		AffectedTag        string
		AffectedDigest     string
		AffectedHarborURL  string
		FinishedAt         int64
		TaskID             primitive.ObjectID
		ScanType           int `json:"-" bson:"-"` //By Severity 1 Med to Critical 2 Network based 3
	}
	digestToVulnsBySeverity := make(map[string][]vulnInfoEx)
	digestToVulnsMedToCritical := make(map[string][]vulnInfoEx)
	digestToVulnsNetworkBased := make(map[string][]vulnInfoEx)
	for cursor.Next(ctx) {
		var task model.ScanTask
		err := cursor.Decode(&task)
		if err != nil {
			return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document error: %w ", err))
		}
		digestToVulnsBySeverity[task.ImageDigest] = []vulnInfoEx{}
		digestToVulnsMedToCritical[task.ImageDigest] = []vulnInfoEx{}
		digestToVulnsNetworkBased[task.ImageDigest] = []vulnInfoEx{}
		for _, vuln := range task.ScanReport.Vulns.Vulnerabilities {
			vex := vulnInfoEx{
				VulnerabilityInfo:  vuln,
				AffectedRepository: task.Repository,
				AffectedTag:        task.Tag,
				AffectedDigest:     task.ImageDigest,
				AffectedHarborURL:  task.HarborURL,
				FinishedAt:         task.FinishedAt,
				TaskID:             task.ID,
				ScanType:           ScanTypeBySeverity,
			}
			//MedToCritical
			if redclair.SeverityGreaterThan(vuln.Severity, redclair.SeverityLow) {

				if !strings.Contains(vuln.CVSS.CVSSv2Vector, "AV:L") {
					//Network based
					vex.ScanType = ScanTypeNetWorkBased
				} else {
					vex.ScanType = ScanTypeByMedToCritical
				}
			}
			digestToVulnsBySeverity[task.ImageDigest] = append(digestToVulnsBySeverity[task.ImageDigest], vex)
		}
		for _, sens := range task.ScanReport.Vulns.Sensitives {
			sens.Description = fmt.Sprintf("Potential file leak: %s", sens.Description)
			vi := model.VulnerabilityInfo{
				Description: sens.Description,
				FeatureName: sens.Name,
				Severity:    redclair.SeverityUnknown,
				Links:       []string{},
			}
			vex := vulnInfoEx{
				VulnerabilityInfo:  vi,
				AffectedRepository: task.Repository,
				AffectedTag:        task.Tag,
				AffectedDigest:     task.ImageDigest,
				AffectedHarborURL:  task.HarborURL,
				FinishedAt:         task.FinishedAt,
				TaskID:             task.ID,
				ScanType:           ScanTypeBySeverity,
			}
			digestToVulnsBySeverity[task.ImageDigest] = append(digestToVulnsBySeverity[task.ImageDigest], vex)
		}
	}
	err = cursor.Err()
	if err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("mongo cursor error: %w", err))
	}

	listItemsSetBySeverity := make(map[string]model.ScanReportListItem)
	listItemsSetMedToCritical := make(map[string]model.ScanReportListItem)
	listItemsSetNetWorkBased := make(map[string]model.ScanReportListItem)
	for _, vulns := range digestToVulnsBySeverity {

		for _, vuln := range vulns {

			key := vuln.ID
			if key == "" {
				// handle sensitive filename
				key = vuln.FeatureName
			}
			if _, ok := listItemsSetBySeverity[key]; !ok {
				listItemsSetBySeverity[key] = model.ScanReportListItem{
					VulnInfo:       vuln.VulnerabilityInfo,
					AffectedImages: &[]model.ScanReportAffectedImage{},
				}
			}
			af := model.ScanReportAffectedImage{
				Repository: vuln.AffectedRepository,
				Tag:        vuln.AffectedTag,
				Digest:     vuln.AffectedDigest,
				HarborURL:  vuln.AffectedHarborURL,
				FinishedAt: vuln.FinishedAt,
				TaskID:     vuln.TaskID,
			}

			*listItemsSetBySeverity[key].AffectedImages = append(*listItemsSetBySeverity[key].AffectedImages, af)
			if vuln.ScanType >= ScanTypeByMedToCritical {

				if _, ok := listItemsSetMedToCritical[key]; !ok {
					listItemsSetMedToCritical[key] = model.ScanReportListItem{
						VulnInfo:       vuln.VulnerabilityInfo,
						AffectedImages: &[]model.ScanReportAffectedImage{},
					}
				}

				*listItemsSetMedToCritical[key].AffectedImages = append(*listItemsSetMedToCritical[key].AffectedImages, af)
			}

			if vuln.ScanType == 3 {
				if _, ok := listItemsSetNetWorkBased[key]; !ok {
					listItemsSetNetWorkBased[key] = model.ScanReportListItem{
						VulnInfo:       vuln.VulnerabilityInfo,
						AffectedImages: &[]model.ScanReportAffectedImage{},
					}
				}
				*listItemsSetNetWorkBased[key].AffectedImages = append(*listItemsSetNetWorkBased[key].AffectedImages, af)
			}
		}
	}

	// convert to list in order to sort easier
	listItemsBySeverity := make([]model.ScanReportListItem, len(listItemsSetBySeverity))
	i := 0
	for _, item := range listItemsSetBySeverity {
		listItemsBySeverity[i] = item
		i++
	}

	listItemsMedToCritical := make([]model.ScanReportListItem, len(listItemsSetMedToCritical))
	i = 0
	for _, item := range listItemsSetMedToCritical {
		listItemsMedToCritical[i] = item
		i++
	}

	// convert to list in order to sort easier
	listItemsNetWorkBased := make([]model.ScanReportListItem, len(listItemsSetNetWorkBased))
	i = 0
	for _, item := range listItemsSetNetWorkBased {
		listItemsNetWorkBased[i] = item
		i++
	}

	sortListItemsBySeverityAndStuff(listItemsBySeverity, true)
	sortListItemsBySeverityAndStuff(listItemsMedToCritical, true)
	sortListItemsBySeverityAndStuff(listItemsNetWorkBased, true)
	mqr := imageVulnerabilitiesMongoResult{
		&listItemsBySeverity,
		&listItemsMedToCritical,
		&listItemsNetWorkBased,
		0,
	}

	finishedAt, err := c.getScanTaskNewestEntryTimestamp()
	if err != nil {
		return nil, NewAnError(http.StatusInternalServerError, fmt.Errorf("getMongoMaxFinishedAt error:%w", err))
	}
	mqr.FinishedAt = finishedAt

	return &mqr, nil
}

func sortListItemsBySeverityAndStuff(vulnerabilities []model.ScanReportListItem, asc bool) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if !asc {
			i, j = j, i
		}
		return redclair.CompareVulnerabilities(vulnerabilities[i].VulnInfo, vulnerabilities[j].VulnInfo)
	})
}

func (c *ImageVulnerabilityCache) bgSync() {
	for {
		select {
		case <-time.After(util.CacheRefreshInterval):
			logging.GetLogger().Info().Msg("Starting ImageVulnerabilities data sync")
			err := c.checkVersionAndSyncData(c.ctx)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed data sync")
			}
		}
	}
}

func (c *ImageVulnerabilityCache) checkVersionAndSyncData(ctx context.Context) error {
	c.ch.Lock()
	defer c.ch.Unlock()

	ok, err := c.ch.CheckVersion()
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("checkVersion error: %w", err))
	}
	if ok {
		return nil
	}

	mqr, err := c.getMongoData(ctx)
	if err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("getMongoData error: %w", err))
	}

	err = c.flushToRedis(ctx, BySeverityKey, *mqr)
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("BySeverity flush to redis error: %w", err))
	}
	err = c.flushToRedis(ctx, MedToCriticalKey, *mqr)
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("MedToCritical flush to redis error: %w", err))
	}
	err = c.flushToRedis(ctx, NetWorkBasedKey, *mqr)
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("NetWorkBased flush to redis error: %w", err))
	}

	err = c.ch.SetCachedTimestamp(mqr.FinishedAt)
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("setRedisMaxFinishedAt error: %w", err))
	}

	return nil
}

func (c *ImageVulnerabilityCache) flushToRedis(ctx context.Context, ftype string, ivmr imageVulnerabilitiesMongoResult) error {

	ctx, cancel := context.WithTimeout(ctx, util.RedisTimeout)

	defer cancel()
	var scanReport *[]model.ScanReportListItem

	if ftype == BySeverityKey {
		scanReport = ivmr.listItemsBySeverity
	} else if ftype == MedToCriticalKey {
		scanReport = ivmr.listItemsMedToCritical
	} else {
		scanReport = ivmr.listItemsNetWorkBased
	}

	key := c.ch.KeyFrom(ftype)

	err := c.redisClient.LTrim(ctx, key, 1, 0).Err()
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("redis %s trim error: %w", key, err))
	}

	for _, v := range *scanReport {
		data, err := json.Marshal(v)
		if err != nil {
			return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("json marshal error: %w", err))
		}
		err = c.redisClient.RPush(ctx, key, data).Err()
		if err != nil {
			return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Redis %s data error %w", key, err))
		}
	}
	return nil
}

func (c *ImageVulnerabilityCache) GetItems(ctx context.Context, riskFilter string, offset int64, limit int64, sortOrder string) ([]model.ScanReportListItem, int64, error) {

	err := c.checkVersionAndSyncData(ctx)
	if err != nil {
		return nil, 0, err
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc"
	}
	severityKey := BySeverityKey
	if riskFilter == "medToCrit" {
		severityKey = MedToCriticalKey
	}
	if riskFilter == "networkBased" {
		severityKey = NetWorkBasedKey
	}

	key := c.ch.KeyFrom(severityKey)

	ctx, cancel := context.WithTimeout(ctx, util.RedisTimeout)
	defer cancel()
	var result []string

	//gen len
	length, err := c.redisClient.LLen(ctx, key).Result()
	sl := make([]model.ScanReportListItem, 0)
	if err != nil {
		return sl, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("get redis cache error:%w", err))
	}
	start := offset

	end := offset + limit - 1
	if end > length-1 {
		end = length - 1
	}
	if sortOrder == "desc" {
		start = length - offset - limit
		if start < 0 {
			start = 0
		}
		end = length - offset - 1
	}

	result, err = c.redisClient.LRange(ctx, key, start, end).Result()

	if err != nil {
		return sl, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("get redis cache error:%w", err))
	}

	for _, v := range result {
		r := model.ScanReportListItem{}
		err := json.Unmarshal([]byte(v), &r)
		if err != nil {
			return sl, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("json  unmarshal error:%w", err))
		}
		sl = append(sl, r)
	}
	if sortOrder != "asc" {
		return reverseReportListItem(sl), length, nil
	}
	return sl, length, nil
}

func reverseReportListItem(s []model.ScanReportListItem) []model.ScanReportListItem {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

package util

import (
	"context"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ImageVulnerabilityCacheInterface interface {
	getMongoData(ctx context.Context)
	checkVersion(ctx context.Context) bool
	checkVersionAndSyncData(ctx context.Context)
	getRedisMaxFinishedAt(ctx context.Context) int64
	getMongoMaxFinishedAt(ctx context.Context) int64
	flushToRedis(ctx context.Context, ftype string) error
	setRedisMaxFinishedAt(ctx context.Context)
	GetResultItem(ctx context.Context, riskFilter string, lan lang.LanguageType, offset int64, limit int64, sortOrder string) ([]scanReportListItem, int64)
	BgSync()
}
type scanReportAffectedImage struct {
	Repository string             `json:"repository"`
	Tag        string             `json:"tag"`
	Digest     string             `json:"digest"`
	HarborURL  string             `json:"harborURL"`
	FinishedAt int64              `json:"finishedAt"`
	TaskID     primitive.ObjectID `json:"taskID"`
}

type scanReportListItem struct {
	VulnInfo       redclair.VulnerabilityInfo `json:"vulnInfo"`
	AffectedImages *[]scanReportAffectedImage `json:"affectedImages"`
}
type ImageVulnerabilityCache struct {
	mongodb                *mongo.Database
	redisClient            *redis.Client
	listItemsBySeverity    *[]scanReportListItem
	listItemsMedToCritical *[]scanReportListItem
	listItemsNetWorkBased  *[]scanReportListItem
	FinishedAt             int64
	DataChannel            chan struct{}
	ctx                    context.Context
	mu                     sync.Mutex
}

const (
	BySeverityKey    = "BySeverity"
	MedToCriticalKey = "MedToCritical"
	NetWorkBasedKey  = "NetWorkBased"
	FinishedAtKey    = "FinishedAt"
	MongoTimeout     = time.Second * 20
	RedisTimeout     = time.Second * 5
)

func NewImageVulnerabilityCache(mongodb *mongo.Database, redisClient *redis.Client, ctx context.Context) *ImageVulnerabilityCache {

	s := ImageVulnerabilityCache{
		mongodb: mongodb, redisClient: redisClient, DataChannel: make(chan struct{}, 1), ctx: ctx,
	}
	go s.BgSync()
	s.DataChannel <- struct{}{}
	return &s
}
func (c *ImageVulnerabilityCache) getMongoData(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, MongoTimeout)
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
	cursor, err := c.mongodb.Collection(model.ScanTasksCollection).Find(ctx, filter)

	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Errorf("Couldn't find document:%s ", err).Error())
	}
	defer cursor.Close(ctx)

	type vulnInfoEx struct {
		// Helper struct that creates one to one mapping between vulnerability and affected image.
		redclair.VulnerabilityInfo
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
			logging.GetLogger().Error().Msg(fmt.Errorf("Couldn't decode document error: %s ", err).Error())
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
				ScanType:           1,
			}
			//MedToCritical
			if redclair.SeverityGreaterThan(vuln.Severity, redclair.SeverityLow) {

				if !strings.Contains(vuln.CVSS.CVSSv2Vector, "AV:L") {
					//Network based
					vex.ScanType = 3
				} else {
					vex.ScanType = 2
				}
			}
			digestToVulnsBySeverity[task.ImageDigest] = append(digestToVulnsBySeverity[task.ImageDigest], vex)
		}
		for _, sens := range task.ScanReport.Vulns.Sensitives {
			sens.Description = fmt.Sprintf("Potential file leak: %s", sens.Description)
			vi := redclair.VulnerabilityInfo{
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
				ScanType:           1,
			}
			digestToVulnsBySeverity[task.ImageDigest] = append(digestToVulnsBySeverity[task.ImageDigest], vex)
		}
	}
	err = cursor.Err()
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Errorf("Cursor error: %s ", err).Error())
	}

	listItemsSetBySeverity := make(map[string]scanReportListItem)
	listItemsSetMedToCritical := make(map[string]scanReportListItem)
	listItemsSetNetWorkBased := make(map[string]scanReportListItem)
	for _, vulns := range digestToVulnsBySeverity {

		for _, vuln := range vulns {

			key := vuln.ID
			if key == "" {
				// handle sensitive filename
				key = vuln.FeatureName
			}
			if _, ok := listItemsSetBySeverity[key]; !ok {
				listItemsSetBySeverity[key] = scanReportListItem{
					VulnInfo:       vuln.VulnerabilityInfo,
					AffectedImages: &[]scanReportAffectedImage{},
				}
			}
			af := scanReportAffectedImage{
				Repository: vuln.AffectedRepository,
				Tag:        vuln.AffectedTag,
				Digest:     vuln.AffectedDigest,
				HarborURL:  vuln.AffectedHarborURL,
				FinishedAt: vuln.FinishedAt,
				TaskID:     vuln.TaskID,
			}

			*listItemsSetBySeverity[key].AffectedImages = append(*listItemsSetBySeverity[key].AffectedImages, af)
			if vuln.ScanType >= 2 {

				if _, ok := listItemsSetMedToCritical[key]; !ok {
					listItemsSetMedToCritical[key] = scanReportListItem{
						VulnInfo:       vuln.VulnerabilityInfo,
						AffectedImages: &[]scanReportAffectedImage{},
					}
				}

				*listItemsSetMedToCritical[key].AffectedImages = append(*listItemsSetMedToCritical[key].AffectedImages, af)
			}

			if vuln.ScanType == 3 {
				if _, ok := listItemsSetNetWorkBased[key]; !ok {
					listItemsSetNetWorkBased[key] = scanReportListItem{
						VulnInfo:       vuln.VulnerabilityInfo,
						AffectedImages: &[]scanReportAffectedImage{},
					}
				}
				*listItemsSetNetWorkBased[key].AffectedImages = append(*listItemsSetNetWorkBased[key].AffectedImages, af)
			}
		}
	}

	// convert to list in order to sort easier
	listItemsBySeverity := make([]scanReportListItem, len(listItemsSetBySeverity))
	i := 0
	for _, item := range listItemsSetBySeverity {
		listItemsBySeverity[i] = item
		i++
	}

	listItemsMedToCritical := make([]scanReportListItem, len(listItemsSetMedToCritical))
	i = 0
	for _, item := range listItemsSetMedToCritical {
		listItemsMedToCritical[i] = item
		i++
	}

	// convert to list in order to sort easier
	listItemsNetWorkBased := make([]scanReportListItem, len(listItemsSetNetWorkBased))
	i = 0
	for _, item := range listItemsSetNetWorkBased {
		listItemsNetWorkBased[i] = item
		i++
	}

	sortListItemsBySeverityAndStuff(listItemsBySeverity, true)
	sortListItemsBySeverityAndStuff(listItemsMedToCritical, true)
	sortListItemsBySeverityAndStuff(listItemsNetWorkBased, true)
	c.mu.Lock()
	c.listItemsBySeverity = &listItemsBySeverity
	c.listItemsMedToCritical = &listItemsMedToCritical
	c.listItemsNetWorkBased = &listItemsNetWorkBased
	c.FinishedAt = c.getMongoMaxFinishedAt(ctx)
	c.mu.Unlock()
	return
}

func sortListItemsBySeverityAndStuff(vulnerabilities []scanReportListItem, asc bool) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		if !asc {
			i, j = j, i
		}

		return redclair.CompareVulnerabilities(vulnerabilities[i].VulnInfo, vulnerabilities[j].VulnInfo)
	})
}

func (c *ImageVulnerabilityCache) BgSync() {
	for {
		select {
		case <-c.DataChannel:
			c.checkVersionAndSyncData(c.ctx)
		}
	}
}

func (c *ImageVulnerabilityCache) checkVersion(ctx context.Context) bool {

	mongoFinishedAt := c.getMongoMaxFinishedAt(ctx)
	redisFinishedAt := c.getRedisMaxFinishedAt(ctx)
	if mongoFinishedAt != -1 && redisFinishedAt != -1 && mongoFinishedAt == redisFinishedAt {
		return true
	}
	return false
}

func (c *ImageVulnerabilityCache) checkVersionAndSyncData(ctx context.Context) {
	if !c.checkVersion(ctx) {
		c.getMongoData(ctx)
		err := c.flushToRedis(ctx, BySeverityKey)
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Errorf("BySeverity flush to redis error:%s", err).Error())
		}
		err = c.flushToRedis(ctx, MedToCriticalKey)
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Errorf("BySeverity flush to redis error:%s", err).Error())

		}
		err = c.flushToRedis(ctx, NetWorkBasedKey)
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Errorf("BySeverity flush to redis error:%s", err).Error())
		}
		c.setRedisMaxFinishedAt(ctx)
		c.listItemsBySeverity = nil
		c.listItemsMedToCritical = nil
		c.listItemsNetWorkBased = nil
		c.FinishedAt = 0
	}
}
func (c *ImageVulnerabilityCache) getRedisMaxFinishedAt(ctx context.Context) int64 {
	ctx, cancel := context.WithTimeout(ctx, RedisTimeout)
	defer cancel()
	val, err := c.redisClient.Get(ctx, FinishedAtKey).Result()
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Errorf("get redis max finishedat error: %s", err).Error())
		return -1
	}
	val64, _ := strconv.ParseInt(val, 10, 64)
	return val64
}

func (c *ImageVulnerabilityCache) setRedisMaxFinishedAt(ctx context.Context) {
	if c.FinishedAt == -1 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, RedisTimeout)
	defer cancel()
	//
	err := c.redisClient.Set(ctx, FinishedAtKey, strconv.FormatInt(c.FinishedAt, 10), 0).Err()
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Errorf("set FinishedAt  redis error：%s", err).Error())
		return
	}
	return
}

func (c *ImageVulnerabilityCache) getMongoMaxFinishedAt(ctx context.Context) int64 {

	ctx, cancel := context.WithTimeout(ctx, MongoTimeout)
	defer cancel()
	filter := bson.D{}

	findOptions := options.FindOne()
	findOptions.SetSort(bson.D{{"finishedAt", -1}})

	singleResult := c.mongodb.Collection(model.ScanTasksCollection).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {

		logging.GetLogger().Error().Msg(fmt.Errorf("singleResult error: %s", singleResult.Err()).Error())
		return -1
	}

	var scanTask model.ScanTask
	err := singleResult.Decode(&scanTask)
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Errorf("Couldn't decode scan task: %s ", err).Error())
		return -1
	}
	return scanTask.FinishedAt
}

func (c *ImageVulnerabilityCache) flushToRedis(ctx context.Context, ftype string) error {

	if c.listItemsBySeverity == nil {
		return fmt.Errorf("listItemsMedToCritical is nil")
	}
	ctx, cancel := context.WithTimeout(ctx, RedisTimeout)

	defer cancel()
	var (
		scanReport *[]scanReportListItem
	)

	if ftype == BySeverityKey {

		scanReport = c.listItemsBySeverity
	} else if ftype == MedToCriticalKey {

		scanReport = c.listItemsMedToCritical
	} else {
		scanReport = c.listItemsNetWorkBased
	}

	c.redisClient.LTrim(ctx, ftype, 1, 0)

	for _, v := range *scanReport {
		data, err := json.Marshal(v)
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Errorf("json marshal error: %s", err).Error())
			return err
		}
		err = c.redisClient.RPush(ctx, ftype, data).Err()
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Errorf("Redis  set BySeverity data error %s", err).Error())
			return err
		}
	}
	return nil
}

func (c *ImageVulnerabilityCache) GetResultItem(ctx context.Context, riskFilter string, offset int64, limit int64, sortOrder string) ([]scanReportListItem, int64) {

	c.checkVersionAndSyncData(ctx)
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc"
	}
	key := BySeverityKey
	if riskFilter == "medToCrit" {
		key = MedToCriticalKey
	}
	if riskFilter == "networkBased" {
		key = NetWorkBasedKey
	}

	ctx, cancel := context.WithTimeout(ctx, RedisTimeout)
	defer cancel()
	var (
		result []string
		err    error
	)

	//gen len
	lenth, err := c.redisClient.LLen(ctx, key).Result()
	var resize int64 = 0
	if offset+limit > lenth {
		resize = lenth % limit
	} else {
		resize = limit
	}
	sl := make([]scanReportListItem, resize)
	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Errorf("get redis cache error:%s", err).Error())
		return sl, 0
	}

	start := offset

	end := offset + limit - 1
	if end > lenth-1 {
		end = lenth - 1
	}

	if sortOrder == "desc" {
		start = lenth - offset - limit
		if start < 0 {
			start = 0
		}
		end = lenth - offset - 1
	}

	result, err = c.redisClient.LRange(ctx, key, start, end).Result()

	if err != nil {
		logging.GetLogger().Error().Msg(fmt.Errorf("get redis cache error:%s", err).Error())
		return sl, 0
	}

	for i, v := range result {
		r := scanReportListItem{}
		err := json.Unmarshal([]byte(v), &r)
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Errorf("json  unmarshal error:%s", err).Error())
		}
		sl[i] = r
	}
	if sortOrder != "asc" {
		return reverse(sl), lenth
	}
	return sl, lenth
}
func reverse(s []scanReportListItem) []scanReportListItem {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

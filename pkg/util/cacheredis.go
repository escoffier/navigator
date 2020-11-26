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
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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
	mongodb     *mongo.Database
	redisClient *redis.Client
	ctx         context.Context
	mu          sync.Mutex
}

const (
	BySeverityKey           = "BySeverity"
	MedToCriticalKey        = "MedToCritical"
	NetWorkBasedKey         = "NetWorkBased"
	FinishedAtKey           = "FinishedAt"
	MongoTimeout            = time.Second * 20
	RedisTimeout            = time.Second * 5
	ScanTypeBySeverity      = 1
	ScanTypeByMedToCritical = 2
	ScanTypeNetWorkBased    = 3
)

func NewImageVulnerabilityCache(mongodb *mongo.Database, redisClient *redis.Client, ctx context.Context) *ImageVulnerabilityCache {

	s := ImageVulnerabilityCache{
		mongodb: mongodb, redisClient: redisClient, ctx: ctx,
	}
	go s.BgSync()
	return &s
}

type mongoQueryResult struct {
	listItemsBySeverity    *[]scanReportListItem
	listItemsMedToCritical *[]scanReportListItem
	listItemsNetWorkBased  *[]scanReportListItem
	FinishedAt             int64
}

func (c *ImageVulnerabilityCache) getMongoData(ctx context.Context) (*mongoQueryResult, error) {
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
		return nil, fmt.Errorf("Couldn't find document:%w ", err)
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
			return nil, fmt.Errorf("Couldn't decode document error: %w ", err)
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
				ScanType:           ScanTypeBySeverity,
			}
			digestToVulnsBySeverity[task.ImageDigest] = append(digestToVulnsBySeverity[task.ImageDigest], vex)
		}
	}
	err = cursor.Err()
	if err != nil {
		return nil, err
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
			if vuln.ScanType >= ScanTypeByMedToCritical {

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
	mqr := mongoQueryResult{
		&listItemsBySeverity,
		&listItemsMedToCritical,
		&listItemsNetWorkBased,
		0,
	}

	FinishedAt, err := c.getMongoMaxFinishedAt(ctx)
	if err != nil {
		return nil, fmt.Errorf("get mongo maxfinishedat error:%w", err)
	} else {
		mqr.FinishedAt = FinishedAt
	}

	return &mqr, nil
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
	timer := time.NewTimer(time.Second * 60)
	for {
		select {
		case <-timer.C:
			c.checkVersionAndSyncData(c.ctx)
		}
	}
}

func (c *ImageVulnerabilityCache) checkVersion(ctx context.Context) (bool, error) {

	mongoFinishedAt, err := c.getMongoMaxFinishedAt(ctx)
	if err != nil {
		return false, err
	}
	redisFinishedAt, err := c.getRedisMaxFinishedAt(ctx)
	if err != nil {
		return false, fmt.Errorf("getredisMaxFinishadAt error: %w ", err)
	}
	if mongoFinishedAt != -1 && redisFinishedAt != -1 && mongoFinishedAt == redisFinishedAt {
		return true, nil
	}
	return false, nil
}

func (c *ImageVulnerabilityCache) checkVersionAndSyncData(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok, err := c.checkVersion(ctx)
	if err != nil {
		return err
	}
	if !ok {
		mqr, err := c.getMongoData(ctx)
		if err != nil {
			return err
		}
		err = c.flushToRedis(ctx, BySeverityKey, *mqr)
		if err != nil {
			return fmt.Errorf("BySeverity flush to redis error:%w", err)
		}
		err = c.flushToRedis(ctx, MedToCriticalKey, *mqr)
		if err != nil {
			return fmt.Errorf("MedToCritical flush to redis error:%w", err)
		}
		err = c.flushToRedis(ctx, NetWorkBasedKey, *mqr)
		if err != nil {
			return fmt.Errorf("NetWorkBased flush to redis error:%w", err)
		}
		c.setRedisMaxFinishedAt(ctx, *mqr)
	}
	return nil
}
func (c *ImageVulnerabilityCache) getRedisMaxFinishedAt(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, RedisTimeout)
	defer cancel()
	val, err := c.redisClient.Get(ctx, FinishedAtKey).Result()
	if err != nil {
		return -1, fmt.Errorf("get redis max finishedat error: %w", err)
	}
	val64, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return -1, fmt.Errorf("redis  parseint [val:%s] error: %w", val, err)
	}
	return val64, nil
}

func (c *ImageVulnerabilityCache) setRedisMaxFinishedAt(ctx context.Context, mqr mongoQueryResult) {
	if mqr.FinishedAt == -1 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, RedisTimeout)
	defer cancel()
	//
	err := c.redisClient.Set(ctx, FinishedAtKey, strconv.FormatInt(mqr.FinishedAt, 10), 0).Err()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("set FinishedAt  redis error：%s")
		return
	}
	return
}

func (c *ImageVulnerabilityCache) getMongoMaxFinishedAt(ctx context.Context) (int64, error) {

	ctx, cancel := context.WithTimeout(ctx, MongoTimeout)
	defer cancel()
	filter := bson.D{}

	findOptions := options.FindOne()
	findOptions.SetSort(bson.D{{"finishedAt", -1}})

	singleResult := c.mongodb.Collection(model.ScanTasksCollection).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		return -1, fmt.Errorf("singleResult error: %w", singleResult.Err())
	}

	var scanTask model.ScanTask
	err := singleResult.Decode(&scanTask)
	if err != nil {
		return -1, fmt.Errorf("Couldn't decode scan task: %w ", err)
	}
	return scanTask.FinishedAt, nil
}

func (c *ImageVulnerabilityCache) flushToRedis(ctx context.Context, ftype string, mqr mongoQueryResult) error {

	ctx, cancel := context.WithTimeout(ctx, RedisTimeout)

	defer cancel()
	var (
		scanReport *[]scanReportListItem
	)

	if ftype == BySeverityKey {

		scanReport = mqr.listItemsBySeverity
	} else if ftype == MedToCriticalKey {

		scanReport = mqr.listItemsMedToCritical
	} else {
		scanReport = mqr.listItemsNetWorkBased
	}

	err := c.redisClient.LTrim(ctx, ftype, 1, 0).Err()
	if err != nil {
		return fmt.Errorf("redis trim error:%w", err)
	}

	for _, v := range *scanReport {
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("json marshal error: %w", err)
		}
		err = c.redisClient.RPush(ctx, ftype, data).Err()
		if err != nil {
			return fmt.Errorf("Redis  set BySeverity data error %w", err)
		}
	}
	return nil
}

func (c *ImageVulnerabilityCache) GetResultItem(ctx context.Context, riskFilter string, offset int64, limit int64, sortOrder string) ([]scanReportListItem, int64, error) {

	err := c.checkVersionAndSyncData(ctx)
	if err != nil {
		return nil, 0, err
	}
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
	var result []string

	//gen len
	lenth, err := c.redisClient.LLen(ctx, key).Result()
	sl := make([]scanReportListItem, 0)
	if err != nil {
		return sl, 0, fmt.Errorf("get redis cache error:%w", err)
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
		return sl, 0, fmt.Errorf("get redis cache error:%w", err)
	}

	for _, v := range result {
		r := scanReportListItem{}
		err := json.Unmarshal([]byte(v), &r)
		if err != nil {
			return sl, 0, fmt.Errorf("json  unmarshal error:%w", err)
		}
		sl = append(sl, r)
	}
	if sortOrder != "asc" {
		return reverse(sl), lenth, nil
	}
	return sl, lenth, nil
}
func reverse(s []scanReportListItem) []scanReportListItem {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

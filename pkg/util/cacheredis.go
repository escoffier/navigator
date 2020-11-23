package util

import (
	"context"
	"encoding/json"
	"fmt"

	"sort"
	"strconv"
	"strings"
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

type syncCache interface {
	GetMongoData()
	CheckVersion() bool
	GetRedisMaxFinishedAt() *int64
	GetMongoMaxFinishedAt() *int64
	FlushToRedisBySeverity()
	FlushToRedisMedToCritical()
	FlushToRedisNetWorkBased()
	SetRedisMaxFinishedAt()
	GetResultItem(riskFilter string, lan lang.LanguageType, offset int64, limit int64, sortOrder string) ([]scanReportListItem, int64)
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
type SyncData struct {
	mongodb                *mongo.Database
	redisClient            *redis.Client
	listItemsBySeverity    *[]scanReportListItem
	listItemsMedToCritical *[]scanReportListItem
	listItemsNetWorkBased  *[]scanReportListItem
	FinishedAt             *int64
	DataChannel            chan string
}

const (
	BySeverityKey    = "BySeverity"
	MedToCriticalKey = "MedToCritical"
	NetWorkBasedKey  = "NetWorkBased"
	FinishedAtKey    = "FinishedAt"
)

func NewSyncData(mongodb *mongo.Database, redisClient *redis.Client) *SyncData {

	s := SyncData{
		mongodb: mongodb, redisClient: redisClient, DataChannel: make(chan string, 1),
	}
	go s.BgSync()
	s.DataChannel <- "Begain"
	return &s

}

func (s *SyncData) GetMongoData() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*100)
	defer cancel()
	//By Severity
	//Med to Critical
	//Network based
	sortOrder := "desc"

	fromDateUnix := time.Now().Add(-1 * time.Hour * 24 * 7).Unix()
	toDateUnix := time.Now().Unix()

	filter := bson.M{
		"finishedAt": bson.M{"$gt": fromDateUnix, "$lt": toDateUnix},
		"status":     model.ScanStatusSucceeded,
	}
	findOptions := options.Find()

	findOptions.SetSort(bson.D{{"finishedAt", 1}})
	cursor, err := s.mongodb.Collection(model.ScanTasksCollection).Find(ctx, filter, findOptions)

	if err != nil {
		fmt.Errorf("Couldn't find document: %w", err)
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
	}

	digestToVulnsBySeverity := make(map[string][]vulnInfoEx)
	digestToVulnsMedToCritical := make(map[string][]vulnInfoEx)
	digestToVulnsNetworkBased := make(map[string][]vulnInfoEx)
	for cursor.Next(ctx) {
		var task model.ScanTask
		err := cursor.Decode(&task)
		if err != nil {
			fmt.Errorf("Couldn't decode document: %w", err)
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
			}
			digestToVulnsBySeverity[task.ImageDigest] = append(digestToVulnsBySeverity[task.ImageDigest], vex)
			//MedToCritical
			if redclair.SeverityGreaterThan(vuln.Severity, redclair.SeverityLow) {

				digestToVulnsMedToCritical[task.ImageDigest] = append(digestToVulnsMedToCritical[task.ImageDigest], vex)
				if !strings.Contains(vuln.CVSS.CVSSv2Vector, "AV:L") {
					//Network based
					digestToVulnsNetworkBased[task.ImageDigest] = append(digestToVulnsNetworkBased[task.ImageDigest], vex)
				}
			}
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
			}
			digestToVulnsBySeverity[task.ImageDigest] = append(digestToVulnsBySeverity[task.ImageDigest], vex)
		}
	}
	err = cursor.Err()
	if err != nil {
		fmt.Errorf("Cursor error: %w", err)
	}

	listItemsSetBySeverity := make(map[string]scanReportListItem)
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
		}
	}
	listItemsSetMedToCritical := make(map[string]scanReportListItem)
	for _, vulns := range digestToVulnsMedToCritical {
		for _, vuln := range vulns {
			key := vuln.ID
			if key == "" {
				// handle sensitive filename
				key = vuln.FeatureName
			}
			if _, ok := listItemsSetMedToCritical[key]; !ok {
				listItemsSetMedToCritical[key] = scanReportListItem{
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
			*listItemsSetMedToCritical[key].AffectedImages = append(*listItemsSetMedToCritical[key].AffectedImages, af)
		}
		//

	}
	listItemsSetNetWorkBased := make(map[string]scanReportListItem)
	for _, vulns := range digestToVulnsNetworkBased {

		for _, vuln := range vulns {
			key := vuln.ID
			if key == "" {
				// handle sensitive filename
				key = vuln.FeatureName
			}

			if _, ok := listItemsSetNetWorkBased[key]; !ok {
				listItemsSetNetWorkBased[key] = scanReportListItem{
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

			*listItemsSetNetWorkBased[key].AffectedImages = append(*listItemsSetNetWorkBased[key].AffectedImages, af)
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

	sortListItemsBySeverityAndStuff(listItemsBySeverity, sortOrder == "desc")
	sortListItemsBySeverityAndStuff(listItemsMedToCritical, sortOrder == "desc")
	sortListItemsBySeverityAndStuff(listItemsNetWorkBased, sortOrder == "desc")

	s.listItemsBySeverity = &listItemsBySeverity
	s.listItemsMedToCritical = &listItemsMedToCritical
	s.listItemsNetWorkBased = &listItemsNetWorkBased
	s.FinishedAt = s.GetMongoMaxFinishedAt()
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

func (s *SyncData) BgSync() {
	for {
		select {
		case <-s.DataChannel:
			s.CheckVersionAndSyncData()
		}
	}
}

func (s *SyncData) CheckVersion() bool {

	mongoFinishedAt := s.GetMongoMaxFinishedAt()
	redisFinishedAt := s.GetRedisMaxFinishedAt()
	if mongoFinishedAt != nil && redisFinishedAt != nil && *mongoFinishedAt == *redisFinishedAt {
		return true
	}
	return false
}

func (s *SyncData) CheckVersionAndSyncData() {
	mongoFinishedAt := s.GetMongoMaxFinishedAt()
	redisFinishedAt := s.GetRedisMaxFinishedAt()
	if mongoFinishedAt != nil && redisFinishedAt != nil && *mongoFinishedAt == *redisFinishedAt {
		return
	}
	s.GetMongoData()
	s.FlushToRedisBySeverity()
	s.FlushToRedisMedToCritical()
	s.FlushToRedisNetWorkBased()
	s.SetRedisMaxFinishedAt()
}
func (s *SyncData) GetRedisMaxFinishedAt() *int64 {
	var ctx = context.Background()
	val, err := s.redisClient.Get(ctx, FinishedAtKey).Result()
	if err != nil {
		var i int64 = 2
		return &i
	}
	val64, _ := strconv.ParseInt(val, 10, 64)
	return &val64
}

func (s *SyncData) SetRedisMaxFinishedAt() {
	if s.FinishedAt == nil {
		return
	}
	var ctx = context.Background()
	//
	err := s.redisClient.Set(ctx, FinishedAtKey, strconv.FormatInt(*s.FinishedAt, 10), 0).Err()
	if err != nil {
		fmt.Errorf("-------------->Set FinishedAt  redis error：%s ", err)
		return
	}
	return
}

func (s *SyncData) GetMongoMaxFinishedAt() *int64 {

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	filter := bson.D{}

	findOptions := options.FindOne()
	findOptions.SetSort(bson.D{{"finishedAt", -1}})

	singleResult := s.mongodb.Collection(model.ScanTasksCollection).FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		fmt.Errorf("singleResult error: %s", singleResult.Err())
		var i int64 = 0
		return &i
	}

	var scanTask model.ScanTask
	err := singleResult.Decode(&scanTask)
	if err != nil {
		fmt.Errorf("Couldn't decode scan task: %s", err)
		return nil
	}
	return &scanTask.FinishedAt
}

func (s *SyncData) FlushToRedisBySeverity() {

	if s.listItemsBySeverity == nil {
		fmt.Errorf("listItemsMedToCritical is nil")
		return
	}
	//开始刷写数据
	//首先清除原有数据
	var ctx = context.Background()

	//开始移除
	s.redisClient.LTrim(ctx, BySeverityKey, 1, 0)
	//开始写入数据
	//RPUSH key value1 [value2]
	for _, v := range *s.listItemsBySeverity {
		data, err := json.Marshal(v)
		if err != nil {
			fmt.Errorf("json marshal error: %s", err)
			return
		}
		err = s.redisClient.RPush(ctx, BySeverityKey, data).Err()
		if err != nil {
			fmt.Errorf("Redis  set BySeverity data error %s", err)

			return
		}
	}


}

func (s *SyncData) FlushToRedisMedToCritical() {
	if s.listItemsMedToCritical == nil {
		fmt.Errorf("listItemsMedToCritical is nil")
		return
	}
	//clear all
	var ctx = context.Background()

	//remove item
	s.redisClient.LTrim(ctx, MedToCriticalKey, 1, 0)
	//RPUSH key value1 [value2]
	for _, v := range *s.listItemsMedToCritical {
		data, err := json.Marshal(v)
		if err != nil {
			fmt.Errorf("json marshal error:%s ", err)
			return
		}
		err = s.redisClient.RPush(ctx, MedToCriticalKey, data).Err()
		if err != nil {
			fmt.Errorf("Redis  set MedToCritical data error %s", err)
			return
		}
	}
}

func (s *SyncData) FlushToRedisNetWorkBased() {
	if s.listItemsNetWorkBased == nil {
		fmt.Errorf("listItemsNetWorkBased is nil")
		return
	}
	//clear all
	var ctx = context.Background()
	//remove item
	s.redisClient.LTrim(ctx, NetWorkBasedKey, 1, 0)

	//remove item
	//RPUSH key value1 [value2]
	for _, v := range *s.listItemsNetWorkBased {
		data, err := json.Marshal(v)
		if err != nil {
			fmt.Errorf("json marshal error:%s", err)
			return
		}
		err = s.redisClient.RPush(ctx, NetWorkBasedKey, data).Err()
		if err != nil {
			fmt.Errorf("Redis set NetWorkBased data error %s", err)
			return
		}
	}
}

func (s *SyncData) GetResultItem(riskFilter string, lan lang.LanguageType, offset int64, limit int64, sortOrder string) ([]scanReportListItem, int64) {

	if !s.CheckVersion() {
		s.GetMongoData()
		s.FlushToRedisBySeverity()
		s.FlushToRedisMedToCritical()
		s.FlushToRedisNetWorkBased()
		s.SetRedisMaxFinishedAt()
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
	var sl = make([]scanReportListItem, 0)
	var ctx = context.Background()
	var (
		result []string
		err    error
	)

	//gen len
	len, err := s.redisClient.LLen(ctx, key).Result()
	if err != nil {
		fmt.Errorf("get redis cache error:%s", err)
		return sl, 0
	}

	start := offset

	end := offset + limit - 1
	if end > len-1 {
		end = len - 1
	}

	if sortOrder == "desc" {
		start = len - offset - limit
		if start < 0 {
			start = 0
		}
		end = len - offset - 1
	}

	result, err = s.redisClient.LRange(ctx, key, start, end).Result()

	if err != nil {
		fmt.Errorf("get redis cache error:%s", err)
		return sl, 0
	}

	for _, v := range result {
		r := scanReportListItem{}
		json.Unmarshal([]byte(v), &r)

		sl = append(sl, r)
	}
	if sortOrder != "asc" {
		return reverse(sl), len
	}
	return sl, len
}
func reverse(s []scanReportListItem) []scanReportListItem {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

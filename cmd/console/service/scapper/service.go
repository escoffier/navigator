package scapper

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ahmetb/go-linq/v3"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/segmentio/kafka-go"
	"github.com/shopspring/decimal"
	"github.com/tealeg/xlsx/v3"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/cis/outputter"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var (
	scapperInstance *Scapper
	svcInstance     *ScapService
	once            sync.Once
)

const (
	testLevelWarn = "WARN"
	testLevelFail = "FAIL"
	testLevelPass = "PASS"
	testLevelInfo = "INFO"
)

func Init(mainCtx context.Context,
	envInfo EnvironmentInfo,
	scapOpts *flag.ScapOpts,
	redisClient *redis.Client,
	rdb *databases.RDBInstance,
	stream rpcstream.MessageStream,
	mqReader mq.Reader,
) error {
	if redisClient == nil {
		return errors.New("illegal argument")
	}
	var err error
	once.Do(func() {
		svcInstance, err = newScapService(scapOpts, rdb, redisClient)
		if err != nil {
			return
		}
		scapperInstance = newScapper(envInfo, scapOpts, svcInstance, rdb, stream)
		err = mqReader.Subscribe(
			outputter.KafkaTopicIvanCompliance,
			"compliance",
			handleComplianceScanResult(rdb),
		)
	})
	return err
}

func handleComplianceScanResult(rdb *databases.RDBInstance) func(ctx context.Context, m kafka.Message) error {
	return func(ctx context.Context, m kafka.Message) error {
		var data RecvScanResultReq
		err := json.Unmarshal(m.Value, &data)
		if err != nil {
			logging.Get().Err(err).Msg("compliance scan json decode fail")
			return err
		}

		// 处理合规扫描返回的结果
		err = RecvScanResults(ctx, rdb.Get(), &data)
		if err != nil {
			logging.Get().Err(err).Msg("failed to handle compliance scan result")
			return err
		}

		return err
	}
}

func GetScapper(ctx context.Context) (*Scapper, bool) {
	return scapperInstance, scapperInstance != nil
}

func GetService(ctx context.Context) (*ScapService, bool) {
	return svcInstance, svcInstance != nil
}

type ScapService struct {
	rdb   *databases.RDBInstance
	cache *redis.Client
}

func newScapService(scapOpts *flag.ScapOpts, rdb *databases.RDBInstance, cache *redis.Client) (*ScapService, error) {
	scapSvc := &ScapService{
		rdb:   rdb,
		cache: cache,
	}

	go func() {
		err := scapSvc.PolicyInit(scapOpts.PolicyCounts)
		if err != nil {
			logging.Get().Error().Msg(fmt.Sprintf("policy init failed, %v", err))
		}
	}()

	return scapSvc, nil
}

func (s *ScapService) PolicyInit(policyCounts int32) error {
	var policy model.PolicyDetailInfo
	tbname := policy.TableName()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	files := []string{
		"/policy/kube-policy.json",
		"/policy/docker-policy.json",
		"/policy/host-policy.json",
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			logging.Get().Err(err).Msgf("read data failed from %s", file)
			continue
		}

		var policies []*model.PolicyDetailInfo
		err = json.Unmarshal(data, &policies)
		if err != nil {
			logging.Get().Err(err).Msgf("json unmarshal policy failed, file : %s", file)
			continue
		}

		// 批量插入，如果主键冲突，则update
		db := s.rdb.Get().WithContext(ctx)
		db.Logger = db.Logger.LogMode(logger.Silent)
		err = db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			UpdateAll: true,
		}).
			Table(tbname).
			CreateInBatches(policies, 30).
			Error
		if err != nil {
			logging.Get().Err(err).Msg("write policy to db failed")
		}
	}

	return nil
}

func (s *ScapService) CheckScanningTask(ctx context.Context, checkType, clusterId string) (bool, error) {
	var task model.ScanHistory
	query := "check_type = ? and cluster_key = ? and state = 1"
	err := s.rdb.GetReadDB().WithContext(ctx).First(&task, query, checkType, clusterId).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

func (s *ScapService) SynScanState(checkHistory *model.ScanHistory) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scap, _ := GetScapper(ctx)

	var scanNodes []model.ScanNodeRecord
	query := "task_id = ?"
	err := s.rdb.Get().WithContext(ctx).Find(&scanNodes, query, checkHistory.TaskID).Error
	if err != nil {
		return errors.Errorf("get scan node record failed, %v", err)
	}

	// get success node
	sucNode := 0
	var finishAt int64
	for _, nodeRecord := range scanNodes {
		if finishAt == 0 {
			finishAt = nodeRecord.FinishedAt
		}

		if nodeRecord.State == model.ScanStateCompleted {
			sucNode++
		}

		if nodeRecord.State != model.ScanStateInProgress {
			continue
		}

		// 获取对应job的状态
		status, err := scap.GetJobStatus(nodeRecord.ClusterKey, nodeRecord.Namespace, nodeRecord.JobName)
		if err != nil {
			logging.Get().Error().Msgf("get jobs status failed, %v.", err)
			continue
		}

		updates := map[string]interface{}{
			"state":       status,
			"finished_at": finishAt,
		}

		nodeRecord.State = status

		switch status {
		case model.ScanStateInProgress: // 如果还有job在运行中
			return nil
		case model.ScanStateCompleted:
			sucNode++
			updates["message"] = "success"
		case model.ScanStateFailed:
			updates["message"] = "sync state"
		}

		query = "task_id = ? and node_name = ? and state=1"
		taskId := nodeRecord.TaskID
		nodename := nodeRecord.NodeName

		// update state
		err = s.rdb.Get().WithContext(ctx).Model(nodeRecord).Where(query, taskId, nodename).Updates(updates).Error
		if err != nil {
			logging.Get().Error().Msgf("updates scan node record failed, %v.", err)
		}
	}

	if finishAt < checkHistory.CreatedAt {
		finishAt = checkHistory.CreatedAt
	}
	// update check history
	checkHistory.FinishedAt = finishAt
	// update scan history
	taskId := checkHistory.TaskID
	tb := model.ScanHistory{
		State:      model.ScanStateCompleted,
		FinishedAt: finishAt,
		SucNode:    int32(sucNode),
	}
	//
	query = "task_id = ? and check_type = ? and state = 1"
	err = s.rdb.Get().WithContext(ctx).Model(tb).Where(query, taskId, checkHistory.CheckType).Select("state", "suc_node", "finished_at").Updates(tb).Error
	if err != nil {
		logging.Get().Error().Msgf("update scan history state=0 failed, task_id : %s, %v.", taskId, err)
	}

	return nil
}

func (s *ScapService) GetCheckHistory(ctx context.Context, offset, limit int, clusterId, checkType, sortBy, sortOrder string) ([]model.ScanHistory, int64, error) {
	// print debug log
	// logging.Get().Debug().Msgf("offset : %v, limit : %v, sortBy : %v, sortOrder : %v.", offset, limit, sortBy, sortOrder)

	pgCtx, mpgCancel := context.WithTimeout(ctx, time.Second*2)
	defer mpgCancel()

	db := s.rdb.Get().WithContext(pgCtx).Model(&model.ScanHistory{})
	if clusterId != "" {
		db = db.Where("cluster_key = ?", clusterId)
	}

	if checkType != "" {
		db = db.Where("check_type = ?", checkType)
	}

	var docNum int64

	if err := db.Count(&docNum).Error; err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("could not count, %w", err))
	}

	if sortBy != "" {
		db = db.Order(clause.OrderByColumn{Column: clause.Column{Name: sortBy}, Desc: strings.ToLower(sortOrder) == "desc"})
	}

	var scanHistory = make([]model.ScanHistory, 0, limit)
	// query := fmt.Sprintf("cluster_key = ? and check_type = ? order by %s %s limit %v offset %v", sortBy, sortOrder, limit, offset)
	// err := s.rdb.Get().WithContext(pgCtx).Find(&scanHistory, query, clusterId, checkType).Error
	err := db.Limit(int(limit)).Offset(int(offset)).Find(&scanHistory).Error
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find scan history, %w", err))
	}

	return scanHistory, docNum, nil
}

func (s *ScapService) GetLatestHistory(ctx context.Context, clusterId string, checkType model.ComplianceCheckType) (string, int64, error) {
	var scanHistory model.ScanHistory
	err := s.rdb.GetReadDB().WithContext(ctx).Select("task_id", "finished_at").
		Where("cluster_key = ? AND check_type = ?", clusterId, checkType).
		Where("state = ? AND finished_at>0 AND suc_node>0", model.ScanStateCompleted).
		Order(clause.OrderByColumn{Column: clause.Column{Name: "finished_at"}, Desc: true}).
		First(&scanHistory).Error
	if err != nil {
		return "", 0, err
	}

	return scanHistory.TaskID, scanHistory.FinishedAt, nil
}

func (s *ScapService) GetNodeCheckDetails(ctx context.Context, nodeName, taskID string, nodeCheckDetails *model.NodeCheckDetails) error {
	node := model.ScanNodeRecord{}
	err := s.rdb.GetReadDB().WithContext(ctx).
		First(&node, "task_id = ? AND node_name = ?", taskID, nodeName).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("")
		return err
	}

	resSvc, ok := assets.GetResourcesService(ctx)
	if !ok {
		return errors.New("assets.GetResourcesService instance get error")
	}

	queryOpt := dal.NodeQuery()
	queryOpt.WithCluster(node.ClusterKey)
	queryOpt.WithCustom("host_name", node.NodeName)

	nodes, err := resSvc.GetNodes(ctx, queryOpt, 0, 1)
	if err != nil {
		return err
	}

	nodeCheckDetails.TaskID = taskID
	nodeCheckDetails.ClusterKey = node.ClusterKey
	nodeCheckDetails.NodeName = nodeName
	nodeCheckDetails.NodeStatus = -1
	nodeCheckDetails.NodeReady = -1
	nodeCheckDetails.ScanStatus = node.State
	if len(nodes) > 0 {
		nodeCheckDetails.NodeStatus = nodes[0].Status
		nodeCheckDetails.NodeReady = int8(nodes[0].Ready)
	}

	return nil
}

func (s *ScapService) GetPolicyInfo(ctx context.Context, policyId string, checkType model.ComplianceCheckType) (*model.PolicyDetailInfo, error) {
	var policy model.PolicyDetailInfo

	// try to get by cache
	key := fmt.Sprintf("%s:%s", checkType, policyId)
	rawJSON, err := s.cache.Get(ctx, key).Bytes()
	if err != nil {
		logging.Get().Info().Err(err).Msg("")
	} else {
		if err = json.Unmarshal(rawJSON, &policy); err == nil {
			return &policy, nil
		}
		logging.Get().Info().Err(err).Msg("")
	}

	// get by db
	condition := "policy_id = ? and check_type = ? and status = 0"
	err = s.rdb.GetReadDB().WithContext(ctx).First(&policy, condition, policyId, checkType).Error
	if err != nil || policy.PolicyId == "" {
		logging.Get().Err(err).Msgf("get policy information failed, policy id : %s, checkType : %s", policyId, checkType)
		return nil, errors.Errorf("get policy information failed, policy id : %s, checkType : %s", policyId, checkType)
	}

	// save to cache
	if rawJSON, err = json.Marshal(policy); err != nil {
		logging.Get().Warn().Err(err).Msg("json.Marshal err")
	} else {
		if err = s.cache.Set(ctx, key, rawJSON, time.Hour+time.Second*time.Duration(rand.Intn(100))).Err(); err != nil {
			logging.Get().Warn().Err(err).Msg("s.cache.Set err")
		}
	}

	return &policy, nil
}

func (s *ScapService) FindBreakdownEntries(ctx context.Context, taskID string, checkType model.ComplianceCheckType, section, udbcp, policyID, checkStatus string) ([]*model.CheckBreakdown, error) {
	db := s.rdb.GetReadDB().WithContext(ctx).Model(&model.ScanResult{})
	if udbcp != "" {
		db = db.Where("udbcp = ?", udbcp)
	}
	if section != "" {
		db = db.Where("section = ?", section)
	}
	if policyID != "" {
		db = db.Where("policy_id = ?", policyID)
	}

	list := make([]*model.CheckBreakdown, 0)
	err := db.Select("COUNT(CASE WHEN state=? THEN 1 END) AS pass,"+
		"COUNT(CASE WHEN state=? THEN 1 END) AS warn,"+
		"COUNT(CASE WHEN state=? THEN 1 END) AS info,"+
		"COUNT(CASE WHEN state=? THEN 1 END) AS fail,"+
		"policy_id,udbcp", model.ScapScanResultStatePASS, model.ScapScanResultStateWARN,
		model.ScapScanResultStateINFO, model.ScapScanResultStateFAIL).
		Group("policy_id,udbcp").
		Find(&list, "check_type = ? AND task_id = ?", checkType, taskID).Error
	if err != nil {
		return nil, errors.Errorf("get scan result failed, %v", err)
	}

	language := lang.Language(ctx)
	for i := range list {
		if checkType == model.ComplianceCheckTargetTypeDocker {
			if strings.HasPrefix(list[i].PolicyNumber, "co") {
				list[i].Runtime = "cri-o"
			} else if strings.HasPrefix(list[i].PolicyNumber, "cd") {
				list[i].Runtime = "containerd"
			} else {
				list[i].Runtime = "docker"
			}
		}

		policy, err := s.GetPolicyInfo(ctx, list[i].PolicyNumber, checkType)
		if err != nil {
			logging.Get().Err(err).Msgf("get policy information failed, policy id : %s, checkType : %s.", list[i].PolicyNumber, checkType)
			continue
		}

		if language == lang.LanguageEN {
			list[i].Section = policy.TitleEn
			list[i].Description = policy.DetailEn
			list[i].UDBCP = policy.ClassifiedEn
		} else {
			list[i].Section = policy.TitleZh
			list[i].Description = policy.DetailZh
			list[i].UDBCP = policy.ClassifiedZh
		}
	}

	// filter and sort
	if checkStatus != "" {
		linq.From(list).Where(func(i interface{}) bool {
			item := i.(*model.CheckBreakdown)
			if checkStatus == "compliance" {
				return item.Fail == 0
			} else if checkStatus == "unCompliance" {
				return item.Fail > 0
			}
			return true
		}).Sort(func(i, j interface{}) bool {
			return i.(*model.CheckBreakdown).PolicyNumber < j.(*model.CheckBreakdown).PolicyNumber
		}).ToSlice(&list)
	} else {
		linq.From(list).Sort(func(i, j interface{}) bool {
			iv := i.(*model.CheckBreakdown)
			jv := j.(*model.CheckBreakdown)
			irate := float64(iv.Fail) / float64(iv.Pass+iv.Warn+iv.Info+iv.Fail)
			jrate := float64(jv.Fail) / float64(jv.Pass+jv.Warn+jv.Info+jv.Fail)

			if irate > jrate {
				return true
			} else if irate < jrate {
				return false
			} else {
				return iv.PolicyNumber < jv.PolicyNumber
			}
		}).ToSlice(&list)
	}

	return list, nil
}

func (s *ScapService) GetPolicyDetails(ctx context.Context, policyDetails *model.PolicyDetails, policyId string, checkType model.ComplianceCheckType) error {
	policy, err := s.GetPolicyInfo(ctx, policyId, checkType)
	if err != nil {
		return errors.Errorf("get policy information failed, policy id : %s, checkType : %s.", policyId, checkType)
	}

	language := lang.Language(ctx)

	policyDetails.PolicyNumber = policyId

	if language == lang.LanguageEN {
		policyDetails.Section = policy.TitleEn
		policyDetails.Description = policy.RemediationEn
		policyDetails.UDBCP = policy.ClassifiedEn
	} else {
		policyDetails.Section = policy.TitleZh
		policyDetails.Description = policy.RemediationZh
		policyDetails.UDBCP = policy.ClassifiedZh
	}

	if policy.PolicyDetailInfoExtraDetail != nil {
		policyDetails.ExtraDetail = &model.PolicyDetailInfoExtraDetail{
			References: policy.PolicyDetailInfoExtraDetail.References,
			Audit:      policy.Audit,
		}

		if language == lang.LanguageEN {
			policyDetails.ExtraDetail.Description = policy.PolicyDetailInfoExtraDetail.DescriptionEn
			policyDetails.ExtraDetail.Rationale = policy.PolicyDetailInfoExtraDetail.RationaleEn
			policyDetails.ExtraDetail.Audit = policy.PolicyDetailInfoExtraDetail.AuditEn
			policyDetails.ExtraDetail.Remediation = policy.PolicyDetailInfoExtraDetail.RemediationEn
			policyDetails.ExtraDetail.Impact = policy.PolicyDetailInfoExtraDetail.ImpactEn
			policyDetails.ExtraDetail.DefaultValue = policy.PolicyDetailInfoExtraDetail.DefaultValueEn
		} else {
			policyDetails.ExtraDetail = &policy.PolicyDetailInfoExtraDetail.PolicyDetailInfoExtraDetail
		}
	} else {
		policyDetails.ExtraDetail = &model.PolicyDetailInfoExtraDetail{
			Description: policy.DetailZh,
			Rationale:   policy.TitleZh,
			Audit:       policy.Audit,
			Remediation: policy.RemediationZh,
			References:  []string{},
		}
		if language == lang.LanguageEN {
			policyDetails.ExtraDetail.Description = policy.DetailEn
			policyDetails.ExtraDetail.Rationale = policy.TitleEn
			policyDetails.ExtraDetail.Remediation = policy.RemediationEn
		}
	}

	return nil
}

func (s *ScapService) GetFileData(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Errorf("get data from %v failed, %v", filename, err)
	}
	logging.Get().Info().Msgf("file content length : %v", len(data))
	return data, nil
}

func (s *ScapService) GetScanResultToFile(language lang.LanguageType, task *model.ExportTask) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var scanRet []model.ScanResult
	query := "task_id = ?"
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, query, task.CheckId).Error
	if err != nil {
		return errors.Errorf("get scan result to file failed, %v", err)
	}
	// print debug log
	// logging.Get().Info().Msgf("get scan result data num : %v.", len(scanRet))
	// xlsx file
	var exfile model.ScapRetData
	// new xlsx file
	file := xlsx.NewFile()
	// save data
	defer func() {
		dir := path.Dir(task.FileName)
		isExist, err := os.Stat(dir)
		if isExist == nil {
			if err != nil {
				logging.Get().Warn().Msgf("os.Stat(dir) failed %v", err)
			}

			if err = os.MkdirAll(dir, os.ModePerm); err != nil {
				logging.Get().Error().Msgf("os.Mkdir(dir, os.ModePerm) failed %v", err)
				return
			}
		}

		err = file.Save(task.FileName)
		if err != nil {
			logging.Get().Error().Msgf("save xlsx file failed, %v", err)
		}
	}()
	// add sheet
	sheet, err := file.AddSheet("Sheet1")
	if err != nil {
		return fmt.Errorf("add sheet failed, %v", err)
	}
	// add row
	row := sheet.AddRow()
	row.WriteStruct(model.GetTitle(language, task.CheckType), -1)

	for _, value := range scanRet {
		policy, err := s.GetPolicyInfo(ctx, value.PolicyID, model.ComplianceCheckType(task.CheckType))
		if err != nil {
			logging.Get().Error().Msgf("get policy %s failed, %v.", value.PolicyID, err)
			continue
		}
		exfile.NodeName = value.NodeName
		exfile.LastTime = time.Unix(value.CreatedAt, 0).Format("2006-01-02 15:04:05")
		exfile.Status = model.GetStatus(language, value.State)
		exfile.PolicyId = value.PolicyID
		exfile.TestResult = value.ActualValue
		if language == lang.LanguageEN {
			exfile.Section = policy.TitleEn
			exfile.Descript = policy.RemediationEn
			exfile.DecDetail = policy.DetailEn
			exfile.Classified = policy.ClassifiedEn
		} else {
			exfile.Section = policy.TitleZh
			exfile.Descript = policy.RemediationZh
			exfile.DecDetail = policy.DetailZh
			exfile.Classified = policy.ClassifiedZh
		}
		if policy.PolicyDetailInfoExtraDetail != nil {
			if language == lang.LanguageEN {
				exfile.Audit = policy.PolicyDetailInfoExtraDetail.AuditEn
				exfile.Remediation = policy.PolicyDetailInfoExtraDetail.RemediationEn
			} else {
				exfile.Audit = policy.PolicyDetailInfoExtraDetail.Audit
				exfile.Remediation = policy.PolicyDetailInfoExtraDetail.Remediation
			}
		}

		if model.ComplianceCheckType(task.CheckType) == model.ComplianceCheckTargetTypeDocker {
			if strings.HasPrefix(value.PolicyID, "co") {
				exfile.Runtime = "cri-o"
			} else if strings.HasPrefix(value.PolicyID, "cd") {
				exfile.Runtime = "containerd"
			} else {
				exfile.Runtime = "docker"
			}
		}

		row = sheet.AddRow()
		row.WriteStruct(&exfile, -1)
	}

	return nil
}

func (s *ScapService) AddScapScanResults(ctx context.Context, rs []*model.ScanResult) error {
	if len(rs) == 0 {
		logging.Get().Warn().
			Msg("add scap scan result, result is empty")
		return nil
	}

	var taskId, nodeName = rs[0].TaskID, rs[0].NodeName
	logging.Get().Info().
		Str("taskId", taskId).
		Str("nodeName", nodeName).
		Str("checkType", string(rs[0].CheckType)).
		Msgf("add scap scan result, total: %d", len(rs))

	var pass, warn, info, fail int
	for i := range rs {
		// 老版本的发送端的数据有id字段，这里不需要设置id值
		rs[i].ID = 0

		policy, err := s.GetPolicyInfo(ctx, rs[i].PolicyID, rs[i].CheckType)
		if err == nil {
			rs[i].Section = policy.TitleZh
			rs[i].UDBCP = policy.ClassifiedZh
		}

		if rs[i].State == "PASS" || rs[i].State == "pass" {
			rs[i].State = model.ScapScanResultStatePASS
			pass++
		} else if (rs[i].CheckType != model.ComplianceCheckTargetTypeDocker && rs[i].State == "WARN") || rs[i].State == "warn" {
			rs[i].State = model.ScapScanResultStateWARN
			warn++
		} else if rs[i].State == "NOTE" || rs[i].State == "INFO" || rs[i].State == "notselected" {
			rs[i].State = model.ScapScanResultStateINFO
			info++
		} else if (rs[i].CheckType == model.ComplianceCheckTargetTypeDocker && rs[i].State == "WARN") || rs[i].State == "FAIL" || rs[i].State == "fail" {
			rs[i].State = model.ScapScanResultStateFAIL
			fail++
		}
	}

	scanRecord := &model.ScanNodeRecord{
		State:      model.ScanStateCompleted,
		Message:    "success",
		FinishedAt: time.Now().Unix(),
		Pass:       pass,
		Fail:       fail,
		Warn:       warn,
		Info:       info,
		PassRate:   decimal.NewFromFloat(float64(pass+warn+info) / float64(pass+warn+info+fail)),
	}

	err := s.rdb.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.ScanResult{}).CreateInBatches(rs, 100).Error
		if err != nil {
			return err
		}

		// 因为kube的还要接受 auto_variate 数据，所以在 auto_variate 那里设置状态为成功。
		if rs[0].CheckType == model.ComplianceCheckTargetTypeKube {
			return nil
		}

		// 收到扫描结果将对应任务设置为完成
		err = tx.Model(scanRecord).
			Select("state", "finished_at", "message", "pass", "warn", "info", "fail", "pass_rate").
			Where("state = ?", model.ScanStateInProgress).
			Where("node_name = ? and task_id = ?", nodeName, taskId).
			Updates(scanRecord).
			Error

		return err
	})

	if err != nil {
		logging.Get().Err(err).
			Str("taskId", taskId).
			Str("nodeName", nodeName).
			Str("checkType", string(rs[0].CheckType)).
			Msg("添加 扫描结果 数据失败")
	}

	return err
}

func (s *ScapService) UpdateSnrVariate(ctx context.Context, taskID, nodeName, checkType, autoVariate string) error {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	scanRecord := &model.ScanNodeRecord{
		State:      model.ScanStateCompleted,
		FinishedAt: time.Now().Unix(),
		Message:    "success",
	}

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()
		err := s.rdb.Get().WithContext(oneCtx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&model.ScanNodeRecord{}).
				Where("task_id = ? and node_name = ? and check_type = ?", taskID, nodeName, checkType).
				Update("auto_variate", autoVariate).Error; err != nil {
				return err
			}

			if checkType == string(model.ComplianceCheckTargetTypeKube) {
				// 收到扫描结果将对应任务设置为完成
				err := tx.
					Model(scanRecord).
					Select("state", "finished_at", "message").
					Where("node_name = ? and task_id = ? and state = ?", nodeName, taskID, model.ScanStateInProgress).
					Updates(scanRecord).
					Error

				if err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil {
			logging.Get().Err(err).
				Str("taskId", taskID).
				Str("nodeName", nodeName).
				Str("checkType", checkType).
				Msg("添加 auto_variate 数据失败")
		}

		return err
	})
}

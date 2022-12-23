package scapper

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ahmetb/go-linq/v3"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"github.com/tealeg/xlsx"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
		scapperInstance = newScapper(envInfo, scapOpts, svcInstance, rdb)

	})
	return err
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
		err = s.rdb.Get().
			WithContext(ctx).
			Clauses(clause.OnConflict{
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

func (s *ScapService) GetUDBCPMap(language lang.LanguageType, policyId string, checkType model.ComplianceCheckType) string {
	var value string
	switch checkType {
	case model.ComplianceCheckTargetTypeKube:
		classified, ok := model.UDBCPKubeMap[policyId]
		if !ok {
			return ""
		}

		if language == lang.LanguageEN {
			value = classified[1]
		} else {
			value = classified[0]
		}
	case model.ComplianceCheckTargetTypeDocker:
		classified, ok := model.UDBCPDockerMap[policyId]
		if !ok {
			return ""
		}
		if language == lang.LanguageEN {
			value = classified[1]
		} else {
			value = classified[0]
		}
	default:
		value = ""
	}

	return value
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

	// try get by cache
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

func (s *ScapService) GetNodeRecordAutoVariate(ctx context.Context, checkId, checkType string) (map[string]map[string]string, error) {
	nodeAutoVar := make(map[string]map[string]string)

	if checkType != "kube" {
		return nodeAutoVar, nil
	}

	var nodeRecord []model.ScanNodeRecord
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&nodeRecord, "task_id = ?", checkId).Error
	if err != nil {
		return nodeAutoVar, errors.Errorf("can not find node scan information, checkId : %s", checkId)
	}

	for _, node := range nodeRecord {
		autoVar := make(map[string]string)
		err = json.Unmarshal(node.AutoVariate, &autoVar)
		if err != nil {
			logging.Get().Error().Msgf("json unmarshal AutoVariate failed, %v.", err)
			continue
		}
		nodeAutoVar[node.NodeName] = autoVar
	}

	if len(nodeAutoVar) == 0 {
		return nodeAutoVar, errors.Errorf("can not get node auto variate data")
	}

	return nodeAutoVar, nil
}

func (s *ScapService) ReplaceAutoVariate(src string, autoVar map[string]string) string {
	dst := src

	for key, value := range autoVar {
		f := strings.Fields(value)
		if len(f) > 1 {
			value = "'" + value + "'"
		}

		dst = strings.ReplaceAll(dst, key, value)
	}

	return dst
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
		policy, err := s.GetPolicyInfo(ctx, list[i].PolicyNumber, checkType)
		if err != nil {
			logging.Get().Err(err).Msgf("get policy information failed, policy id : %s, checkType : %s.", list[i].PolicyNumber, checkType)
			continue
		}

		if language == lang.LanguageEN {
			list[i].Section = policy.TitleEn
			list[i].Description = policy.DetailEn
			list[i].UDBCP = s.GetUDBCPMap(language, list[i].PolicyNumber, checkType)
		} else {
			list[i].Section = policy.TitleZh
			list[i].Description = policy.DetailZh
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
	} else {
		policyDetails.Section = policy.TitleZh
		policyDetails.Description = policy.RemediationZh
	}

	policyDetails.UDBCP = s.GetUDBCPMap(language, policyId, checkType)
	if policy.PolicyDetailInfoExtraDetail != nil {
		policyDetails.ExtraDetail = &model.PolicyDetailInfoExtraDetail{References: policy.PolicyDetailInfoExtraDetail.References}

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

func (s *ScapService) GetScanResultToFile(task *model.ExportTask) error {
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
	row.WriteStruct(model.GetTitleZh(), -1)

	for _, value := range scanRet {
		policy, err := s.GetPolicyInfo(ctx, value.PolicyID, model.ComplianceCheckType(task.CheckType))
		if err != nil {
			logging.Get().Error().Msgf("get policy %s failed, %v.", value.PolicyID, err)
			continue
		}
		exfile.NodeName = value.NodeName
		exfile.LastTime = time.Unix(value.CreatedAt, 0).Format("2006-01-02 15:04:05")
		exfile.Status = model.GetStatusZh(value.State)
		exfile.PolicyId = value.PolicyID
		exfile.Section = policy.TitleZh
		exfile.Descript = policy.RemediationZh
		exfile.DecDetail = policy.DetailZh
		exfile.Classified = s.GetUDBCPMap(lang.LanguageZH, value.PolicyID, model.ComplianceCheckType(task.CheckType))
		if policy.PolicyDetailInfoExtraDetail != nil {
			exfile.Audit = policy.PolicyDetailInfoExtraDetail.Audit
			exfile.Remediation = policy.PolicyDetailInfoExtraDetail.Remediation
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
		// TODO: 暂时这样，id应该发送端修改
		rs[i].ID = 0
		rs[i].UDBCP = s.GetUDBCPMap(lang.LanguageZH, rs[i].PolicyID, rs[i].CheckType)

		policy, err := s.GetPolicyInfo(ctx, rs[i].PolicyID, rs[i].CheckType)
		if err == nil {
			rs[i].Section = policy.TitleZh
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
		// Todo: 我认为两个请求能合并到一起
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

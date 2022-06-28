package scapper

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/tealeg/xlsx"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
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
	scapOpts *flag.ScapOpts,
	redisClient *redis.Client,
	rdb *databases.RDBInstance,
) error {
	if redisClient == nil {
		return errors.New("illegal argument")
	}
	var err error
	once.Do(func() {
		svcInstance, err = newScapService(scapOpts, rdb)
		if err != nil {
			return
		}
		scapperInstance = newScapper(scapOpts, svcInstance, rdb)

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
	rdb *databases.RDBInstance
}

func newScapService(scapOpts *flag.ScapOpts, rdb *databases.RDBInstance) (*ScapService, error) {
	scapSvc := &ScapService{
		rdb: rdb,
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
		data, err := ioutil.ReadFile(file)
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

		// 批量插入，如果主键冲突，则ignore
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

func (s *ScapService) CheckScanningTask(ctx context.Context, checkType, clusterId string, timeout int64) (bool, error) {
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

func (s *ScapService) SynScanState(checkHistory *model.CheckHistoryEntry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scap, _ := GetScapper(ctx)

	var scanNodes []model.ScanNodeRecord
	query := "task_id = ?"
	err := s.rdb.Get().WithContext(ctx).Find(&scanNodes, query, checkHistory.CheckID).Error
	if err != nil {
		return errors.Errorf("get scan node record failed, %v", err)
	}

	//get success node
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

		//update state
		err = s.rdb.Get().WithContext(ctx).Model(nodeRecord).Where(query, taskId, nodename).Updates(updates).Error
		if err != nil {
			logging.Get().Error().Msgf("updates scan node record failed, %v.", err)
		}
	}

	if finishAt < checkHistory.CreatedAt {
		finishAt = checkHistory.CreatedAt
	}
	//update check history
	checkHistory.FinishedAt = finishAt
	//update scan history
	taskId := checkHistory.CheckID
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

func (s *ScapService) GetCheckHistory(ctx context.Context, offset, limit int64, clusterId, checkType, sortBy, sortOrder string) ([]model.CheckHistoryEntry, int64, error) {
	//print debug log
	//logging.Get().Debug().Msgf("offset : %v, limit : %v, sortBy : %v, sortOrder : %v.", offset, limit, sortBy, sortOrder)

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
	//query := fmt.Sprintf("cluster_key = ? and check_type = ? order by %s %s limit %v offset %v", sortBy, sortOrder, limit, offset)
	//err := s.rdb.Get().WithContext(pgCtx).Find(&scanHistory, query, clusterId, checkType).Error
	err := db.Limit(int(limit)).Offset(int(offset)).Find(&scanHistory).Error
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find scan history, %w", err))
	}

	items := make([]model.CheckHistoryEntry, 0)

	for _, value := range scanHistory {
		var data model.CheckHistoryEntry
		data.CheckType = checkType
		data.ClusterName = value.ClusterName
		data.ClusterID = value.ClusterKey
		data.Operator = value.Operator
		data.CheckID = value.TaskID
		data.CreatedAt = value.CreatedAt
		data.FinishedAt = value.FinishedAt
		data.PolicyId = value.PolicyID
		data.NumSuccessful = int64(value.SucNode)
		//data.NumFailed = value.FailNode
		//check finish state
		if value.State == model.ScanStateInProgress {
			// ！！！！这里把通过k8s同步的逻辑删除调 @liuyang @lingximo

			//err = s.SynScanState(&data)
			//if err != nil {
			//	logging.Get().Error().Msgf("syn scan history failed, %v.", err)
			//}
			//
			//if data.FinishedAt != 0 {
			//	data.State = 2
			//} else {
			//	data.State = 1
			//}
			data.State = 1
		} else if value.State == model.ScanStateCompleted {
			data.State = 2
		} else {
			data.State = 3
		}

		items = append(items, data)
	}

	return items, docNum, nil
}

func (s *ScapService) GetLatestHistory(ctx context.Context, clusterId, checkType, sortBy, sortOrder string) (string, error) {
	pgCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()

	var scanHistory []model.ScanHistory
	condition := fmt.Sprintf("cluster_key = ? and check_type = ? order by %s %s", sortBy, sortOrder)
	err := s.rdb.GetReadDB().WithContext(pgCtx).Find(&scanHistory, condition, clusterId, checkType).Error
	if err != nil {
		return "", errors.Errorf("get scan history failed, %v", err)
	}

	for _, value := range scanHistory {
		if value.State != model.ScanStateCompleted || value.FinishedAt <= 0 || value.SucNode == 0 {
			continue
		}
		return value.TaskID, nil
	}

	return "", errors.Errorf("can not find correct records")
}

func (s *ScapService) GetClassified(ctx context.Context, policyId, checkType string) string {
	var value string
	ckType := model.ComplianceCheckType(checkType)
	switch ckType {
	case model.ComplianceCheckTargetTypeKube:
		classified, ok := model.ClassifiedKubeMap[policyId]
		if !ok {
			return ""
		}
		value = classified[0]
		if lang.Language(ctx) == lang.LanguageEN {
			value = classified[1]
		}

	case model.ComplianceCheckTargetTypeDocker:
		classified, ok := model.ClassifiedDockerMap[policyId]
		if !ok {
			return ""
		}
		value = classified[0]
		if lang.Language(ctx) == lang.LanguageEN {
			value = classified[1]
		}

	default:
		value = ""
	}

	return value
}

func (s *ScapService) GetClassifiedByLanguage(language lang.LanguageType, policyId, checkType string) string {
	var value string
	ckType := model.ComplianceCheckType(checkType)
	switch ckType {
	case model.ComplianceCheckTargetTypeKube:
		classified, ok := model.ClassifiedKubeMap[policyId]
		if !ok {
			return ""
		}
		value = classified[0]
		if language == lang.LanguageEN {
			value = classified[1]
		}

	case model.ComplianceCheckTargetTypeDocker:
		classified, ok := model.ClassifiedDockerMap[policyId]
		if !ok {
			return ""
		}
		value = classified[0]
		if language == lang.LanguageEN {
			value = classified[1]
		}

	default:
		value = ""
	}

	return value
}

func (s *ScapService) GetNodeChecKubeDetails(ctx context.Context, nodeName, checkID, checkType string, nodeCheckDetails *model.NodeCheckDetails) error {
	autoVars, err := s.GetNodeRecordAutoVariate(ctx, checkID, checkType)
	if err != nil {
		return errors.Errorf("get node auto variate, %v", err)
	}

	var scanRet []model.ScanResult
	query := "node_name = ? and task_id = ?"
	err = s.rdb.GetReadDB().Find(&scanRet, query, nodeName, checkID).Error
	if err != nil {
		return errors.Errorf("get node scan result failed, %v", err)
	}

	if len(scanRet) == 0 {
		return nil
	}

	nodeCheckDetails.Status = "completed"
	nodeCheckDetails.CheckID = checkID
	nodeCheckDetails.NodeName = nodeName
	autoVar := autoVars[nodeName]

	for _, value := range scanRet {
		var cpMap model.ComplianceMapEntry
		policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
		if err != nil {
			logging.Get().Warn().Msgf("get policy info failed, policy id : %s.", value.PolicyID)
			continue
		}
		cpMap.PolicyId = policy.Id
		cpMap.Remediation = s.ReplaceAutoVariate(policy.RemediationZh, autoVar)
		cpMap.Description = policy.DetailZh
		cpMap.Section = policy.TitleZh

		if lang.Language(ctx) == lang.LanguageEN {
			cpMap.Remediation = s.ReplaceAutoVariate(policy.RemediationEn, autoVar)
			cpMap.Description = policy.DetailEn
			cpMap.Section = policy.TitleEn
		}

		cpMap.PolicyNumber = value.PolicyID
		cpMap.TestStatus = value.State
		cpMap.Classified = s.GetClassified(ctx, value.PolicyID, checkType)

		nodeCheckDetails.ComplianceMap = append(nodeCheckDetails.ComplianceMap, cpMap)
	}

	return nil
}

func (s *ScapService) GetNodeCheckDockerDetails(ctx context.Context, nodeName, checkID, checkType string, nodeCheckDetails *model.NodeCheckDetails) error {
	var scanRet []model.ScanResult
	query := "node_name = ? and task_id = ?"
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, query, nodeName, checkID).Error
	if err != nil {
		return errors.Errorf("get node scan result failed, %v", err)
	}

	if len(scanRet) == 0 {
		return nil
	}

	nodeCheckDetails.Status = "completed"
	nodeCheckDetails.CheckID = checkID
	nodeCheckDetails.NodeName = nodeName

	for _, value := range scanRet {
		var cpMap model.ComplianceMapEntry
		policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
		if err != nil {
			logging.Get().Warn().Msgf("get policy info failed, policy id : %s.", value.PolicyID)
			continue
		}

		cpMap.PolicyId = policy.Id
		cpMap.Remediation = value.RemediationZh
		cpMap.Description = policy.DetailZh
		cpMap.Section = policy.TitleZh

		if lang.Language(ctx) == lang.LanguageEN {
			cpMap.Remediation = value.RemediationEn
			cpMap.Description = policy.DetailEn
			cpMap.Section = policy.TitleEn
		}

		cpMap.PolicyNumber = value.PolicyID
		cpMap.TestStatus = value.State
		cpMap.Classified = s.GetClassified(ctx, value.PolicyID, checkType)

		nodeCheckDetails.ComplianceMap = append(nodeCheckDetails.ComplianceMap, cpMap)
	}

	return nil
}

func (s *ScapService) GetNodeCheckHostDetails(ctx context.Context, nodeName, checkID, checkType string, nodeCheckDetails *model.NodeCheckDetails) error {
	var scanRet []model.ScanResult
	query := "node_name = ? and task_id = ?"
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, query, nodeName, checkID).Error
	if err != nil {
		return errors.Errorf("get node scan result failed, %v", err)
	}

	if len(scanRet) == 0 {
		return nil
	}

	nodeCheckDetails.Status = "completed"
	nodeCheckDetails.CheckID = checkID
	nodeCheckDetails.NodeName = nodeName

	for _, value := range scanRet {
		var cpMap model.ComplianceMapEntry
		policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
		if err != nil {
			logging.Get().Warn().Msgf("get policy info failed, policy id : %s.", value.PolicyID)
			continue
		}

		cpMap.PolicyId = policy.Id
		cpMap.Remediation = policy.DetailZh
		cpMap.Description = policy.TitleZh
		if lang.Language(ctx) == lang.LanguageEN {
			cpMap.Remediation = policy.DetailEn
			cpMap.Description = policy.TitleEn
		}

		cpMap.PolicyNumber = value.PolicyID
		cpMap.TestStatus = value.State
		cpMap.Classified = s.GetClassified(ctx, value.PolicyID, checkType)

		nodeCheckDetails.ComplianceMap = append(nodeCheckDetails.ComplianceMap, cpMap)
	}

	return nil
}

func (s *ScapService) GetNodeState(ctx context.Context, waitingOn, errorOn, successOn *[]string, checkId string) error {
	var scanNode []model.ScanNodeRecord
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&scanNode, "task_id = ?", checkId).Error
	if err != nil {
		return errors.Errorf("can not find scan node record, %v", err)
	}
	//get node state
	for _, node := range scanNode {
		switch node.State {
		case model.ScanStateInProgress:
			*waitingOn = util.AppendIfMissing(*waitingOn, node.NodeName)
		case model.ScanStateCompleted:
			*successOn = util.AppendIfMissing(*successOn, node.NodeName)
		case model.ScanStateFailed:
			*errorOn = util.AppendIfMissing(*errorOn, node.NodeName)
		default:
			break
		}
	}

	return nil
}

func (s *ScapService) GetPolicyInfo(ctx context.Context, policyId, checkType string) (*model.PolicyDetailInfo, error) {
	var policy model.PolicyDetailInfo
	condition := "policy_id = ? and check_type = ? and status = 0"
	err := s.rdb.GetReadDB().WithContext(ctx).Take(&policy, condition, policyId, checkType).Error
	if err != nil || policy.PolicyId == "" {
		logging.Get().Err(err).Msgf("get policy information failed, policy id : %s, checkType : %s", policyId, checkType)
		return nil, errors.Errorf("get policy information failed, policy id : %s, checkType : %s", policyId, checkType)
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
		err = json.Unmarshal([]byte(node.AutoVariate), &autoVar)
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

func (s *ScapService) GetKubeBreakdownEntries(ctx context.Context, checkMap map[string]*model.CheckBreakdown, checkId, checkType string) error {
	var scanRet []model.ScanResult
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, "task_id = ?", checkId).Error
	if err != nil {
		return errors.Errorf("get scan result failed, %v", err)
	}
	//get scan result
	for _, value := range scanRet {
		_, ok := checkMap[value.PolicyID]
		if !ok {
			policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
			if err != nil {
				logging.Get().Err(err).Msgf("get policy information failed, policy id : %s, checkType : %s.", value.PolicyID, checkType)
				continue
			}

			title := policy.TitleZh
			detail := policy.DetailZh
			if lang.Language(ctx) == lang.LanguageEN {
				title = policy.TitleEn
				detail = policy.DetailEn
			}

			checkMap[value.PolicyID] = &model.CheckBreakdown{
				PolicyNumber: value.PolicyID,
				Section:      title,
				Description:  detail,
			}
			checkMap[value.PolicyID].Classified = s.GetClassified(ctx, value.PolicyID, checkType)
			checkMap[value.PolicyID].PolicyId = policy.Id
		}

		testStatus := value.State
		switch testStatus {
		case testLevelFail:
			checkMap[value.PolicyID].NumFailed++
		case testLevelWarn:
			checkMap[value.PolicyID].NumWarn++
		case testLevelPass:
			checkMap[value.PolicyID].NumSuccessful++
		case testLevelInfo:
			checkMap[value.PolicyID].NumInfo++
		default:
			break
		}
	}

	return nil
}

func (s *ScapService) GetKubePolicyDetails(ctx context.Context, policyDetails *model.PolicyDetails, policyId, checkType, checkId string) error {
	autoVars, err := s.GetNodeRecordAutoVariate(ctx, checkId, checkType)
	if err != nil {
		return errors.Errorf("get node auto variate failed, %v", err)
	}

	policy, err := s.GetPolicyInfo(ctx, policyId, checkType)
	if err != nil {
		return errors.Errorf("get policy information failed, policy id : %s, checkType : %s.", policyId, checkType)
	}

	var scanRet []model.ScanResult
	query := "task_id = ? and policy_id = ?"
	err = s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, query, checkId, policyId).Error
	if err != nil {
		return errors.Errorf("get scan result failed by policy id : %s, %v", policyId, err)
	}

	policyDetails.Audit = policy.Audit
	policyDetails.PolicyNumber = policyId

	for _, value := range scanRet {
		var nodeRet model.PolicyNodeRet
		nodeRet.NodeName = value.NodeName
		autoVar := autoVars[nodeRet.NodeName]
		nodeRet.TestStatus = value.State
		nodeRet.Remediation = s.ReplaceAutoVariate(policy.RemediationZh, autoVar)
		if lang.Language(ctx) == lang.LanguageEN {
			nodeRet.Remediation = s.ReplaceAutoVariate(policy.RemediationEn, autoVar)
		}

		switch nodeRet.TestStatus {
		case testLevelFail:
			policyDetails.NumFailed++
			policyDetails.FailedOn = append(policyDetails.FailedOn, nodeRet)
		case testLevelWarn:
			policyDetails.NumWarn++
			policyDetails.WarnOn = append(policyDetails.WarnOn, nodeRet)
		case testLevelPass:
			policyDetails.NumSuccessful++
			policyDetails.SuccessfulOn = append(policyDetails.SuccessfulOn, nodeRet)
		case testLevelInfo:
			policyDetails.NumInfo++
			policyDetails.InfoOn = append(policyDetails.InfoOn, nodeRet)
		default:
		}
	}

	return nil
}

func (s *ScapService) GetHostBreakdownEntries(ctx context.Context, checkMap map[string]*model.CheckBreakdown, checkId, checkType string) error {
	var scanRet []model.ScanResult
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, "task_id = ?", checkId).Error
	if err != nil {
		return errors.Errorf("get scan result failed, %v", err)
	}
	//get scan result
	for _, value := range scanRet {
		_, ok := checkMap[value.PolicyID]
		if !ok {
			policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
			if err != nil {
				logging.Get().Error().Msgf("get policy information failed, policy id : %s, checkType : %s.", value.PolicyID, checkType)
				continue
			}

			title := policy.TitleZh
			if lang.Language(ctx) == lang.LanguageEN {
				title = policy.TitleEn
			}
			checkMap[value.PolicyID] = &model.CheckBreakdown{
				PolicyNumber: value.PolicyID,
				Description:  title,
			}

			checkMap[value.PolicyID].Classified = s.GetClassified(ctx, value.PolicyID, checkType)
			checkMap[value.PolicyID].PolicyId = policy.Id
		}

		switch value.State {
		case "fail":
			checkMap[value.PolicyID].NumFailed++
		case "notselected":
			checkMap[value.PolicyID].NumInfo++
		case "pass":
			checkMap[value.PolicyID].NumSuccessful++
		default:
			break
		}
	}

	return nil
}

func (s *ScapService) GetHostPolicyDetails(ctx context.Context, policyDetails *model.PolicyDetails, policyId, checkType, checkId string) error {
	policy, err := s.GetPolicyInfo(ctx, policyId, checkType)
	if err != nil {
		return errors.Errorf("get policy information failed, policy id : %s, checkType : %s.", policyId, checkType)
	}

	var scanRet []model.ScanResult
	query := "task_id = ? and policy_id = ?"
	err = s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, query, checkId, policyId).Error
	if err != nil {
		return errors.Errorf("get scan result failed by policy id : %s, %v", policyId, err)
	}

	policyDetails.Audit = policy.Audit
	policyDetails.PolicyNumber = policyId

	for _, value := range scanRet {
		var nodeRet model.PolicyNodeRet
		nodeRet.NodeName = value.NodeName
		nodeRet.TestStatus = value.State
		nodeRet.Remediation = policy.DetailZh
		if lang.Language(ctx) == lang.LanguageEN {
			nodeRet.Remediation = policy.DetailEn
		}

		switch nodeRet.TestStatus {
		case "fail":
			policyDetails.NumFailed++
			policyDetails.FailedOn = append(policyDetails.FailedOn, nodeRet)
		case "notselected":
			policyDetails.NumInfo++
			policyDetails.InfoOn = append(policyDetails.InfoOn, nodeRet)
		case "pass":
			policyDetails.NumSuccessful++
			policyDetails.SuccessfulOn = append(policyDetails.SuccessfulOn, nodeRet)
		default:
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

func (s *ScapService) GetScanResultToFile(task *model.ExportTask, language lang.LanguageType) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var scanRet []model.ScanResult
	query := "task_id = ?"
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, query, task.CheckId).Error
	if err != nil {
		return errors.Errorf("get scan result to file failed, %v", err)
	}
	//print debug log
	//logging.Get().Info().Msgf("get scan result data num : %v.", len(scanRet))
	//xlsx file
	var exfile model.ScapRetData
	//new xlsx file
	file := xlsx.NewFile()
	//save data
	defer func() {
		err = file.Save(task.FileName)
		if err != nil {
			logging.Get().Error().Msgf("save xlsx file failed, %v", err)
		}
	}()
	//add sheet
	sheet, err := file.AddSheet("Sheet1")
	if err != nil {
		return fmt.Errorf("add sheet failed, %v", err)
	}
	//add row
	row := sheet.AddRow()
	title := model.GetTitleEn()
	if language == lang.LanguageZH {
		title = model.GetTitleZh()
	}
	row.WriteStruct(title, -1)

	for _, value := range scanRet {
		policy, err := s.GetPolicyInfo(ctx, value.PolicyID, task.CheckType)
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
		exfile.Classified = s.GetClassifiedByLanguage(language, value.PolicyID, task.CheckType)
		if language == lang.LanguageEN {
			exfile.Section = policy.TitleEn
			exfile.Descript = policy.RemediationEn
			exfile.DecDetail = policy.DetailEn
			exfile.Status = value.State
		}
		row = sheet.AddRow()
		row.WriteStruct(&exfile, -1)
	}

	return nil
}

func (s *ScapService) GetDockerBreakdownEntries(ctx context.Context, checkMap map[string]*model.CheckBreakdown, checkId, checkType string) error {
	var scanRet []model.ScanResult
	err := s.rdb.GetReadDB().WithContext(ctx).Find(&scanRet, "task_id = ?", checkId).Error
	if err != nil {
		return errors.Errorf("get scan result failed, %v", err)
	}
	//get scan result
	for _, value := range scanRet {
		_, ok := checkMap[value.PolicyID]
		if !ok {
			policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
			if err != nil {
				logging.Get().Error().Msgf("get policy information failed, policy id : %s, checkType : %s.", value.PolicyID, checkType)
				continue
			}

			title := policy.TitleZh
			detail := policy.DetailZh
			if lang.Language(ctx) == lang.LanguageEN {
				title = policy.TitleEn
				detail = policy.DetailEn
			}

			checkMap[value.PolicyID] = &model.CheckBreakdown{
				PolicyNumber: value.PolicyID,
				Section:      title,
				Description:  detail,
			}

			checkMap[value.PolicyID].Classified = s.GetClassified(ctx, value.PolicyID, checkType)
			checkMap[value.PolicyID].PolicyId = policy.Id
		}

		testStatus := value.State
		switch testStatus {
		case "WARN":
			checkMap[value.PolicyID].NumFailed++
		case "NOTE":
			checkMap[value.PolicyID].NumInfo++
		case "PASS":
			checkMap[value.PolicyID].NumSuccessful++
		case "INFO":
			checkMap[value.PolicyID].NumInfo++
		default:
			break
		}
	}

	return nil
}

func (s *ScapService) GetDockerPolicyDetails(ctx context.Context, policyDetails *model.PolicyDetails, policyId, checkType, checkId string) error {
	var scanRet []model.ScanResult
	query := "task_id = ? and policy_id = ?"
	err := s.rdb.Get().WithContext(ctx).Find(&scanRet, query, checkId, policyId).Error
	if err != nil {
		return errors.Errorf("get scan result failed by policy id : %s, %v", policyId, err)
	}

	policyDetails.PolicyNumber = policyId

	for _, value := range scanRet {
		var nodeRet model.PolicyNodeRet
		nodeRet.NodeName = value.NodeName
		nodeRet.TestStatus = value.State
		nodeRet.Remediation = value.RemediationZh
		if lang.Language(ctx) == lang.LanguageEN {
			nodeRet.Remediation = value.RemediationEn
		}

		switch nodeRet.TestStatus {
		case "NOTE":
			policyDetails.NumInfo++
			policyDetails.InfoOn = append(policyDetails.InfoOn, nodeRet)
		case "WARN":
			policyDetails.NumFailed++
			nodeRet.TestStatus = "FAIL"
			policyDetails.FailedOn = append(policyDetails.FailedOn, nodeRet)
		case "PASS":
			policyDetails.NumSuccessful++
			policyDetails.SuccessfulOn = append(policyDetails.SuccessfulOn, nodeRet)
		case "INFO":
			policyDetails.NumInfo++
			policyDetails.InfoOn = append(policyDetails.InfoOn, nodeRet)
		default:
		}
	}

	return nil
}

func (s *ScapService) AddScapScanResult(ctx context.Context, r *model.ScanResult) error {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()
		return s.rdb.Get().WithContext(oneCtx).Model(&model.ScanResult{}).Create(r).Error
	})
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
		Str("checkType", rs[0].CheckType).
		Msgf("add scap scan result, total: %d", len(rs))

	scanRecord := &model.ScanNodeRecord{
		State:      model.ScanStateCompleted,
		FinishedAt: time.Now().Unix(),
		Message:    "success",
	}

	err := s.rdb.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {

		err := tx.Model(&model.ScanResult{}).CreateInBatches(rs, 100).Error
		if err != nil {
			return err
		}

		// 因为kube的还要接受 auto_variate 数据，所以在 auto_variate 那里设置状态为成功。
		// Todo: 我认为两个请求能合并到一起
		if rs[0].CheckType == string(model.ComplianceCheckTargetTypeKube) {
			return nil
		}

		// 收到扫描结果将对应任务设置为完成
		err = tx.
			Model(scanRecord).
			Select("state", "finished_at", "message").
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
			Str("checkType", rs[0].CheckType).
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

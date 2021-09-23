package scapper

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"github.com/tealeg/xlsx"
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

func Init(mainCtx context.Context,
	scapOpts *flag.ScapOpts,
	redisClient *redis.Client,
	pgDsn string,
	postgresDB *rdbtools.GormWrapper,
) error {
	if redisClient == nil {
		return errors.New("illegal argument")
	}
	var err error
	once.Do(func() {
		svcInstance, err = newScapService(scapOpts, postgresDB)
		if err != nil {
			return
		}
		scapperInstance = newScapper(scapOpts, svcInstance, pgDsn, postgresDB)

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
	postgresDB *rdbtools.GormWrapper
}

func newScapService(scapOpts *flag.ScapOpts, postgresDB *rdbtools.GormWrapper) (*ScapService, error) {
	scapSvc := &ScapService{
		postgresDB: postgresDB,
	}

	go func() {
		err := scapSvc.PolicyInit(scapOpts.PolicyCounts)
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Sprintf("policy init failed, %v", err))
		}
	}()

	return scapSvc, nil
}

func (s *ScapService) PolicyInit(policyCounts int32) error {
	var policyNum int64
	var policy model.PolicyDetailInfo
	tbname := policy.TableName()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err := s.postgresDB.Get().WithContext(ctx).Table(tbname).Count(&policyNum).Error
	if err != nil {
		return errors.Errorf("get policy count failed, %v", err)
	}
	//print debug log
	logging.GetLogger().Info().Msgf("default policy counts : %v, actual policy counts : %v.", policyCounts, policyNum)
	if policyNum >= int64(policyCounts) {
		return nil
	}

	files := []string{
		"/policy/kube-policy.txt",
		"/policy/docker-policy.txt",
		"/policy/host-policy.txt",
	}

	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			logging.GetLogger().Error().Msgf("read data failed from %s, %v.", file, err)
			continue
		}

		var policys []model.PolicyDetailInfo
		err = json.Unmarshal(data, &policys)
		if err != nil {
			logging.GetLogger().Error().Msgf("json unmarshal policy failed, file : %s, %v", file, err)
			continue
		}
		//print debug log
		logging.GetLogger().Info().Msgf("policy count : %v.", len(policys))
		//write policy to pg
		for _, rule := range policys {
			policyNum = 0
			err = s.postgresDB.Get().Where(ctx).Table(tbname).Where("policy_id = ? and check_type = ?", rule.PolicyId, rule.CheckType).Count(&policyNum).Error
			if err != nil {
				logging.GetLogger().Error().Msgf("get policy_id = %s failed, %v.", rule.PolicyId, err)
				continue
			}

			if policyNum > 0 {
				continue
			}

			err = s.postgresDB.Get().WithContext(ctx).Table(tbname).Create(&rule).Error
			if err != nil {
				logging.GetLogger().Error().Msgf("write policy to postgre db failed, %v.", err)
			}
		}
	}

	return nil
}

func (s *ScapService) CheckScanningTask(ctx context.Context, checkType, clusterId string, timeout int64) error {
	var task model.ScanHistory
	query := "check_type = ? and cluster_key = ? and state = 1"
	err := s.postgresDB.Get().WithContext(ctx).First(&task, query, checkType, clusterId).Error
	if err == nil || task.TaskID == "" {
		return nil
	}

	var nodeTask []model.ScanNodeRecord
	err = s.postgresDB.Get().WithContext(ctx).Where(&model.ScanNodeRecord{TaskID: task.TaskID}).Find(&nodeTask).Error
	if err != nil {
		return errors.Errorf("get node's scan job task failed, %w", err)
	}

	if len(nodeTask) == 0 {
		err = s.postgresDB.Get().WithContext(ctx).Where(&model.ScanHistory{TaskID: task.TaskID}).Delete(&task).Error
		if err != nil {
			return errors.Errorf("delete invalid history task failed, %w", err)
		}
		return nil
	}

	sucNum := 0
	nowTime := time.Now().Unix()
	var finishTime, createTime int64
	for i := 0; i < len(nodeTask); i++ {
		createTime = nodeTask[i].CreatedAt
		state := nodeTask[i].State
		if state == 1 {
			continue
		}

		if state == 0 {
			sucNum++
		}

		finishTime = nodeTask[i].FinishedAt
	}

	if sucNum > 0 || (nowTime-createTime) > timeout {
		task.State = 0
		task.FinishedAt = finishTime
		task.SucNode = int32(sucNum)
		err = s.postgresDB.Get().WithContext(ctx).Where(&model.ScanHistory{TaskID: task.TaskID}).Select("*").Updates(task).Error
		if err != nil {
			return errors.Errorf("update history task failed, %w", err)
		}
		return nil
	}

	return errors.Errorf("have been scanning task")
}

func (s *ScapService) GetCheckHistory(ctx context.Context, offset, limit int64, clusterId, checkType, sortBy, sortOrder string) ([]model.CheckHistoryEntry, int, error) {
	//print debug log
	//logging.GetLogger().Debug().Msgf("offset : %v, limit : %v, sortBy : %v, sortOrder : %v.", offset, limit, sortBy, sortOrder)

	pgCtx, mpgCancel := context.WithTimeout(ctx, time.Second*2)
	defer mpgCancel()

	var scanHistory []model.ScanHistory
	query := fmt.Sprintf("cluster_key = ? and check_type = ? order by %s %s limit %v offset %v", sortBy, sortOrder, limit, offset)
	err := s.postgresDB.Get().WithContext(pgCtx).Find(&scanHistory, query, clusterId, checkType).Error
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find scan history, %w", err))
	}

	finishState := 0
	items := make([]model.CheckHistoryEntry, 0)
	docNum := len(scanHistory)
	for _, value := range scanHistory {
		var data model.CheckHistoryEntry
		data.CheckType = checkType
		data.ClusterName = value.ClusterName
		data.ClusterID = value.ClusterKey
		data.Operator = value.Operator
		data.CheckID = value.TaskID
		data.CreatedAt = value.CreatedAt
		data.FinishedAt = value.FinishedAt
		//check finish state
		if data.FinishedAt > 0 {
			finishState = 1
		}
		//update finish state
		if data.FinishedAt == 0 && finishState != 0 {
			err = s.postgresDB.Get().WithContext(pgCtx).Where(&model.ScanHistory{TaskID: value.TaskID}).Update("state", 0).Error
			if err != nil {
				logging.GetLogger().Error().Msgf("update scan history state=0 failed, %v.", err)
			}
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
	err := s.postgresDB.Get().WithContext(pgCtx).Find(&scanHistory, condition, clusterId, checkType).Error
	if err != nil {
		return "", errors.Errorf("get scan history failed, %v", err)
	}

	for _, value := range scanHistory {
		if value.State != 0 || value.FinishedAt <= 0 || value.SucNode == 0 {
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
	err = s.postgresDB.Get().Find(&scanRet, query, nodeName, checkID).Error
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
			logging.GetLogger().Warn().Msgf("get policy info failed, policy id : %s.", value.PolicyID)
			continue
		}

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
	err := s.postgresDB.Get().WithContext(ctx).Find(&scanRet, query, nodeName, checkID).Error
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
			logging.GetLogger().Warn().Msgf("get policy info failed, policy id : %s.", value.PolicyID)
			continue
		}

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
	err := s.postgresDB.Get().WithContext(ctx).Find(&scanRet, query, nodeName, checkID).Error
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
			logging.GetLogger().Warn().Msgf("get policy info failed, policy id : %s.", value.PolicyID)
			continue
		}

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
	err := s.postgresDB.Get().WithContext(ctx).Find(&scanNode, "task_id = ?", checkId).Error
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
	err := s.postgresDB.Get().WithContext(ctx).Take(&policy, condition, policyId, checkType).Error
	if err != nil || policy.PolicyId == "" {
		return nil, errors.Errorf("get policy information failed, policy id : %s, checkType : %s", policyId, checkType)
	}

	return &policy, nil
}

func (s *ScapService) GetNodeRecordAutoVariate(ctx context.Context, checkId, checkType string) (map[string]map[string]string, error) {
	nodeAutoVar := make(map[string]map[string]string, 0)

	if checkType != "kube" {
		return nodeAutoVar, nil
	}

	var nodeRecord []model.ScanNodeRecord
	err := s.postgresDB.Get().WithContext(ctx).Find(&nodeRecord, "task_id = ?", checkId).Error
	if err != nil {
		return nodeAutoVar, errors.Errorf("can not find node scan information, checkId : %s", checkId)
	}

	for _, node := range nodeRecord {
		autoVar := make(map[string]string, 0)
		err = json.Unmarshal([]byte(node.AutoVariate), &autoVar)
		if err != nil {
			logging.GetLogger().Error().Msgf("json unmarshal AutoVariate failed, %v.", err)
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

		dst = strings.Replace(dst, key, value, -1)
	}

	return dst
}

func (s *ScapService) GetKubeBreakdownEntries(ctx context.Context, checkMap map[string]*model.CheckBreakdown, checkId, checkType string) error {
	var scanRet []model.ScanResult
	err := s.postgresDB.Get().WithContext(ctx).Find(&scanRet, "task_id = ?", checkId).Error
	if err != nil {
		return errors.Errorf("get scan result failed, %v", err)
	}
	//get scan result
	for _, value := range scanRet {
		_, ok := checkMap[value.PolicyID]
		if !ok {
			policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
			if err != nil {
				logging.GetLogger().Error().Msgf("get policy information failed, policy id : %s, checkType : %s.", value.PolicyID, checkType)
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
		}

		testStatus := value.State
		switch testStatus {
		case "FAIL":
			checkMap[value.PolicyID].NumFailed++
		case "WARN":
			checkMap[value.PolicyID].NumWarn++
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
	err = s.postgresDB.Get().WithContext(ctx).Find(&scanRet, query, checkId, policyId).Error
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
		case "FAIL":
			policyDetails.NumFailed++
			policyDetails.FailedOn = append(policyDetails.FailedOn, nodeRet)
		case "WARN":
			policyDetails.NumWarn++
			policyDetails.WarnOn = append(policyDetails.WarnOn, nodeRet)
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

func (s *ScapService) GetHostBreakdownEntries(ctx context.Context, checkMap map[string]*model.CheckBreakdown, checkId, checkType string) error {
	var scanRet []model.ScanResult
	err := s.postgresDB.Get().WithContext(ctx).Find(&scanRet, "task_id = ?", checkId).Error
	if err != nil {
		return errors.Errorf("get scan result failed, %v", err)
	}
	//get scan result
	for _, value := range scanRet {
		_, ok := checkMap[value.PolicyID]
		if !ok {
			policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
			if err != nil {
				logging.GetLogger().Error().Msgf("get policy information failed, policy id : %s, checkType : %s.", value.PolicyID, checkType)
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
		}

		testStatus := value.State
		switch testStatus {
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
	err = s.postgresDB.Get().WithContext(ctx).Find(&scanRet, query, checkId, policyId).Error
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

func (s *ScapService) GetScanResultToFile(ctx context.Context, file *xlsx.File, task *model.ExportTask, language lang.LanguageType) error {
	var scanRet []model.ScanResult
	query := "task_id = ?"
	err := s.postgresDB.Get().WithContext(ctx).Find(&scanRet, query, task.CheckId).Error
	if err != nil {
		return errors.Errorf("get scan result to file failed, %v", err)
	}

	var exfile model.ScapRetData

	sheet, err := file.AddSheet("Sheet1")
	if err != nil {
		return fmt.Errorf("add sheet failed, %v", err)
	}

	row := sheet.AddRow()
	title := model.GetTitleEn()
	if language == lang.LanguageZH {
		title = model.GetTitleZh()
	}
	row.WriteStruct(title, -1)

	for _, value := range scanRet {
		policy, err := s.GetPolicyInfo(ctx, value.PolicyID, task.CheckType)
		if err != nil {
			logging.GetLogger().Error().Msgf("get policy %s failed, %v.", value.PolicyID, err)
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
	err := s.postgresDB.Get().WithContext(ctx).Find(&scanRet, "task_id = ?", checkId).Error
	if err != nil {
		return errors.Errorf("get scan result failed, %v", err)
	}
	//get scan result
	for _, value := range scanRet {
		_, ok := checkMap[value.PolicyID]
		if !ok {
			policy, err := s.GetPolicyInfo(ctx, value.PolicyID, checkType)
			if err != nil {
				logging.GetLogger().Error().Msgf("get policy information failed, policy id : %s, checkType : %s.", value.PolicyID, checkType)
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
	err := s.postgresDB.Get().WithContext(ctx).Find(&scanRet, query, checkId, policyId).Error
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
		return s.postgresDB.Get().WithContext(oneCtx).Model(&model.ScanResult{}).Create(r).Error
	})
}

func (s *ScapService) AddScapScanResults(ctx context.Context, rs []*model.ScanResult) error {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	err := s.postgresDB.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, r := range rs {
			err := s.AddScapScanResult(ctx, r)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *ScapService) UpdateSnrVariate(ctx context.Context, taskID, nodeName, checkType, autoVariate string) error {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, oneCancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer oneCancel()
		return s.postgresDB.Get().WithContext(oneCtx).Model(&model.ScanNodeRecord{}).
			Where("task_id = ? and node_name = ? and check_type = ?", taskID, nodeName, checkType).
			Update("auto_variate", autoVariate).Error
	})
}

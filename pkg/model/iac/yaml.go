package iac

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	goPkgIac "gitlab.com/security-rd/go-pkg/iac/pkg/scan"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

const (
	OperatorSystem = "system"

	YamlTaskScanTypeManual = "manual"
	YamlTaskScanTypePeriod = "period"
	YamlTaskScanTypeUpdate = "update"

	YamlTaskStatusPreparing = "preparing"
	YamlTaskStatusWaiting   = "waiting"
	YamlTaskStatusScanning  = "scanning"
	YamlTaskStatusComplete  = "complete"
	YamlTaskStatusFailed    = "failed"

	YamlTaskFailReasonDBFails = "internal.db_fails"

	YamlRecordStatusInitial  = "initial"
	YamlRecordStatusWaiting  = "waiting"
	YamlRecordStatusScanning = "scanning"
	YamlRecordStatusComplete = "complete"
	YamlRecordStatusFailed   = "failed"

	YamlResultStatusInitial  = "initial"
	YamlResultStatusWaiting  = "waiting"
	YamlResultStatusComplete = "complete"
	YamlResultStatusFailed   = "failed"

	YamlRecordRateStatusUnknown  = "unknown"
	YamlRecordRateStatusInThreat = "inThreat"
	YamlRecordRateStatusSecure   = "secure"

	YamlResultSeverityLow      = "LOW"
	YamlResultSeverityMedium   = "MEDIUM"
	YamlResultSeverityHigh     = "HIGH"
	YamlResultSeverityCritical = "CRITICAL"

	timeFormat = "2006-01-02 15:04:05"
)

type Resource struct {
	ClusterKey string `json:"cluster_key"`
	Namespace  string `json:"namespace"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Generation int64  `json:"generation"`
}

type YamlSchedule struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	TemplateID  int       `json:"template_id"`
	Schedule    string    `json:"schedule"`
	Config      []byte    `json:"config"`
	Status      int       `json:"status"`
	NextTime    time.Time `json:"next_time"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (YamlSchedule) TableName() string {
	return "ivan_iac_yaml_schedules"
}

func FindYamlSchedules(ctx context.Context, db *gorm.DB, filter map[string]interface{}) ([]YamlSchedule, error) {
	schedules := make([]YamlSchedule, 0)
	err := db.WithContext(ctx).Where(filter).Find(&schedules).Error
	return schedules, err
}

func CreateYamlSchedule(ctx context.Context, db *gorm.DB, task YamlSchedule) (YamlSchedule, error) {
	return task, db.WithContext(ctx).Create(&task).Error
}

func UpdateYamlSchedule(ctx context.Context, db *gorm.DB, filter map[string]interface{}, updates map[string]interface{}) error {
	return db.WithContext(ctx).Model(&YamlSchedule{}).Where(filter).Updates(updates).Error
}

type TemplateRules []string

func (t *TemplateRules) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("gorm.Scan failed to assert CustomKV: %v", value)
	}

	result := TemplateRules{}
	if len(bytes) == 0 {
		bytes = []byte("[]")
	}
	err := json.Unmarshal(bytes, &result)
	*t = result
	return err
}

func (t TemplateRules) Value() (driver.Value, error) {
	bt := make([]byte, 0)
	if t == nil {
		return bt, nil
	}

	bt, err := json.Marshal(t)
	if err != nil {
		return bt, nil
	}
	return bt, nil
}

type YamlTemplate struct {
	ID          int           `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Rules       TemplateRules `json:"rules"`
	Creator     string        `json:"creator"`
	Updater     string        `json:"updater"`
	Builtin     bool          `json:"builtin"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

func (YamlTemplate) TableName() string {
	return "ivan_iac_yaml_rule_templates"
}

func FindYamlTemplatesByName(ctx context.Context, db *gorm.DB, name, hackEqualName string, options map[string]interface{}) (int64, []YamlTemplate, error) {
	templates := make([]YamlTemplate, 0)
	db = db.WithContext(ctx).Model(&YamlTemplate{}).Where("name like ?", "%"+name+"%")
	if offset, ok := options["offset"].(int); (ok && offset == 0) || hackEqualName != "" {
		db = db.Or("name = ?", hackEqualName)
	}

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindYamlTemplatesByName count fails")
		return 0, nil, err
	}

	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err = db.Find(&templates).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindYamlTemplatesByName find fails")
		return 0, nil, err
	}

	return count, templates, err
}

func CountYamlTemplatesByName(ctx context.Context, db *gorm.DB, name string) (int64, error) {
	count := int64(0)
	err := db.WithContext(ctx).Model(&YamlTemplate{}).Where("name like ?", "%"+name+"%").Count(&count).Error
	return count, err
}

func FindYamlTemplates(ctx context.Context, db *gorm.DB, filter map[string]interface{}) ([]YamlTemplate, error) {
	templates := make([]YamlTemplate, 0)
	err := db.WithContext(ctx).Where(filter).Find(&templates).Error
	return templates, err
}

func CreateYamlTemplate(ctx context.Context, db *gorm.DB, task YamlTemplate) (YamlTemplate, error) {
	return task, db.WithContext(ctx).Create(&task).Error
}

func UpdateYamlTemplate(ctx context.Context, db *gorm.DB, filter map[string]interface{}, updates map[string]interface{}) error {
	return db.WithContext(ctx).Model(&YamlTemplate{}).Where(filter).Updates(updates).Error
}

func DeleteYamlTemplate(ctx context.Context, db *gorm.DB, filter map[string]interface{}) error {
	return db.WithContext(ctx).Where(filter).Delete(&YamlTemplate{}).Error
}

type YamlTemplateSnapshot struct {
	ID          int           `json:"id"`
	TemplateID  int           `json:"template_id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Rules       TemplateRules `json:"rules"`
	Creator     string        `json:"creator"`
	Updater     string        `json:"updater"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

func (YamlTemplateSnapshot) TableName() string {
	return "ivan_iac_yaml_rule_template_snapshots"
}

func FindYamlTemplateSnapshotsByIDs(ctx context.Context, db *gorm.DB, ids []int) ([]YamlTemplateSnapshot, error) {
	snapshots := make([]YamlTemplateSnapshot, 0)
	err := db.WithContext(ctx).Where("id in ?", ids).Find(&snapshots).Error
	return snapshots, err
}

func FindYamlTemplateSnapshots(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) ([]YamlTemplateSnapshot, error) {
	snapshots := make([]YamlTemplateSnapshot, 0)
	db = db.WithContext(ctx).Where(filter)
	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err := db.Find(&snapshots).Error
	return snapshots, err
}

func CreateYamlTemplateSnapshot(ctx context.Context, db *gorm.DB, task YamlTemplateSnapshot) (YamlTemplateSnapshot, error) {
	return task, db.WithContext(ctx).Create(&task).Error
}

type YamlRule struct {
	ID           int    `json:"id"`
	BuiltinID    string `json:"builtin_id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Severity     string `json:"severity"`
	ThirdPartyID string `json:"third_party_id"`
}

func (YamlRule) TableName() string {
	return "ivan_iac_yaml_rules"
}

func CreateYamlRules(ctx context.Context, db *gorm.DB, rules []YamlRule) error {
	return db.WithContext(ctx).CreateInBatches(rules, 100).Error
}

func FindYamlRulesByBuiltinIDs(ctx context.Context, db *gorm.DB, builtinIDs []string) ([]YamlRule, error) {
	rules := make([]YamlRule, 0)
	err := db.WithContext(ctx).Where("builtin_id in ?", builtinIDs).Find(&rules).Error
	return rules, err
}

func FindYamlRulesByConditions(ctx context.Context, db *gorm.DB, name string, severity []string, options map[string]interface{}) (int64, []YamlRule, error) {
	rules := make([]YamlRule, 0)
	db = db.WithContext(ctx).Model(&YamlRule{})
	if name != "" {
		db = db.Where("name like ?", "%"+name+"%")
	}
	if len(severity) != 0 {
		db = db.Where("severity in ?", severity)
	}

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindYamlRulesByConditions count fails")
		return 0, nil, err
	}

	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err = db.Find(&rules).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindYamlRulesByConditions find fails")
		return 0, nil, err
	}

	return count, rules, err
}

func FindYamlRules(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) ([]YamlRule, error) {
	rules := make([]YamlRule, 0)
	db = db.WithContext(ctx).Where(filter)
	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err := db.Find(&rules).Error
	return rules, err
}

type YamlTask struct {
	ID           int       `json:"id"`
	ScanType     string    `json:"scan_type"`
	ScheduleID   int       `json:"schedule_id"`
	TemplateID   int       `json:"template_id"`
	TemplateName string    `json:"template_name"`
	Total        int       `json:"total"`
	Success      int       `json:"success"`
	Status       string    `json:"status"`
	Duration     int       `json:"duration"`
	Creator      string    `json:"creator"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (YamlTask) TableName() string {
	return "ivan_iac_yaml_tasks"
}
func FindYamlTasksByScanTypeStatus(ctx context.Context, db *gorm.DB, scanTypes, statuses []string, options map[string]interface{}) (int64, []YamlTask, error) {
	tasks := make([]YamlTask, 0)
	db = db.WithContext(ctx).Model(&YamlTask{})
	if len(scanTypes) != 0 {
		db.Where("scan_type in ?", scanTypes)
	}
	if len(statuses) != 0 {
		db.Where("status in ?", statuses)
	}

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindYamlTasksByScanTypeStatus count fails")
		return 0, nil, err
	}

	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err = db.Find(&tasks).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindYamlTasksByScanTypeStatus find fails")
		return 0, nil, err
	}

	return count, tasks, err
}

func FindYamlTasks(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) ([]YamlTask, error) {
	tasks := make([]YamlTask, 0)
	db = db.WithContext(ctx).Where(filter)
	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err := db.Find(&tasks).Error
	return tasks, err
}

func CountYamlTasks(ctx context.Context, db *gorm.DB, filter map[string]interface{}) (int64, error) {
	count := int64(0)
	err := db.WithContext(ctx).Model(&YamlTask{}).Where(filter).Count(&count).Error
	return count, err
}

func CreateYamlTask(ctx context.Context, db *gorm.DB, task YamlTask) (YamlTask, error) {
	return task, db.WithContext(ctx).Create(&task).Error
}

func UpdateYamlTask(ctx context.Context, db *gorm.DB, filter map[string]interface{}, updates map[string]interface{}) error {
	return db.WithContext(ctx).Model(&YamlTask{}).Where(filter).Updates(updates).Error
}

type YamlRecord struct {
	ID                 int       `json:"id"`
	TaskID             int       `json:"task_id"`
	TemplateID         int       `json:"template_id"`
	TemplateName       string    `json:"template_name"`
	ResourceClusterKey string    `json:"resource_cluster_key"`
	ResourceNamespace  string    `json:"resource_namespace"`
	ResourceKind       string    `json:"resource_kind"`
	ResourceName       string    `json:"resource_name"`
	ResourceGeneration int64     `json:"resource_generation"`
	Status             string    `json:"status"`
	SuccessRate        float64   `json:"success_rate"`
	ResultID           int       `json:"result_id"`
	FailReason         string    `json:"fail_reason"`
	ResourceOnline     bool      `json:"resource_online"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func (YamlRecord) TableName() string {
	return "ivan_iac_yaml_records"
}

func FindYamlRecordsByConditions(ctx context.Context, db *gorm.DB, name, namespace, templateName, hackEqualTemplateName string, clusterKeys, kinds, statuses []string, startTime, endTime int64, options map[string]interface{}) ([]YamlRecord, error) {
	records := make([]YamlRecord, 0)

	sql := makeWhereByConditions2(ctx, name, namespace, templateName, hackEqualTemplateName, clusterKeys, kinds, statuses, startTime, endTime)
	sql = "SELECT s1.*" + sql
	if order, ok := options["order"].(string); ok {
		sql += " ORDER BY s1." + order
	}
	if limit, ok := options["limit"].(int); ok {
		sql += fmt.Sprintf(" LIMIT %d", limit)
	}
	if offset, ok := options["offset"].(int); ok {
		sql += fmt.Sprintf(" OFFSET %d", offset)
	}
	fmt.Println("select sql: ", sql)
	err := db.Raw(sql).Scan(&records).Error

	return records, err
}

func CountYamlRecordsByConditions(ctx context.Context, db *gorm.DB, name, namespace, templateName, hackEqualTemplateName string, clusterKeys, kinds, statuses []string, startTime, endTime int64) (int64, error) {
	count := int64(0)

	sql := makeWhereByConditions2(ctx, name, namespace, templateName, hackEqualTemplateName, clusterKeys, kinds, statuses, startTime, endTime)
	sql = "SELECT COUNT(DISTINCT s1.id)" + sql
	fmt.Println("count sql: ", sql)
	err := db.Raw(sql).Scan(&count).Error

	return count, err
}

func makeWhereByConditions2(ctx context.Context, name, namespace, templateName, hackEqualTemplateName string, clusterKeys, kinds, statuses []string, startTime, endTime int64) string {
	sql := " FROM ivan_iac_yaml_records s1 " +
		"JOIN (" +
		"    SELECT resource_cluster_key, resource_namespace, resource_kind, resource_name, MAX(id) as max_id" +
		"    FROM ivan_iac_yaml_records" +
		"    WHERE resource_online = 1" +
		"    GROUP BY resource_cluster_key, resource_namespace, resource_kind, resource_name" +
		") s2 ON s1.id = s2.max_id "

	if name != "" {
		sql += fmt.Sprintf(" AND s1.resource_name like '%s'", "%"+name+"%")
	}
	if namespace != "" {
		sql += fmt.Sprintf(" AND s1.resource_namespace like '%s'", "%"+namespace+"%")
	}
	if templateName != "" {
		if hackEqualTemplateName != "" {
			sql += fmt.Sprintf(" AND (s1.template_name like '%s' OR s1.template_name = '%s')", "%"+templateName+"%", hackEqualTemplateName)
		} else {
			sql += fmt.Sprintf(" AND s1.template_name like '%s'", "%"+templateName+"%")
		}
	}
	if len(clusterKeys) != 0 {
		s := "("
		for i := range clusterKeys {
			s += "'" + clusterKeys[i] + "',"
		}
		s = s[:len(s)-1] + ")"
		sql += fmt.Sprintf(" AND s1.resource_cluster_key in %s", s)
	}
	if len(kinds) != 0 {
		s := "("
		for i := range kinds {
			s += "'" + kinds[i] + "',"
		}
		s = s[:len(s)-1] + ")"
		sql += fmt.Sprintf(" AND s1.resource_kind in %s", s)
	}
	dbStatuses := ""
	secureOrInThreat := 0
	rateSymbol := ""
	if len(statuses) != 0 {
		for i := range statuses {
			if statuses[i] == YamlRecordRateStatusUnknown {
				dbStatuses = YamlRecordStatusInitial
			}
			if statuses[i] == YamlRecordRateStatusSecure {
				secureOrInThreat += 1
			}
			if statuses[i] == YamlRecordRateStatusInThreat {
				secureOrInThreat += 2
			}
		}
	}
	if secureOrInThreat == 3 { // secure && inThreat
		rateSymbol = "<="
	}
	if secureOrInThreat == 2 { // inThreat
		rateSymbol = "<"
	}
	if secureOrInThreat == 1 { // secure
		rateSymbol = "="
	}
	if rateSymbol != "" {
		if dbStatuses != "" {
			sql += fmt.Sprintf(" AND (s1.success_rate %s 1 OR s1.status = '%s')", rateSymbol, dbStatuses)
		} else {
			sql += fmt.Sprintf(" AND (s1.success_rate %s 1 AND s1.status = '%s')", rateSymbol, YamlRecordStatusComplete)
		}
	} else {
		if dbStatuses != "" {
			sql += fmt.Sprintf(" AND s1.status = '%s'", dbStatuses)
		}
	}

	if startTime != 0 {
		sql += fmt.Sprintf(" AND s1.created_at >= '%s'", time.UnixMilli(startTime).Format(timeFormat))
	}
	if endTime != 0 {
		sql += fmt.Sprintf(" AND s1.created_at <= '%s'", time.UnixMilli(endTime).Format(timeFormat))
	}
	return sql
}

func makeWhereByConditions(ctx context.Context, db *gorm.DB, name, namespace, templateName, hackEqualTemplateName string, clusterKeys, kinds, statuses []string, startTime, endTime int64) *gorm.DB {
	db = db.WithContext(ctx).Table(YamlRecord{}.TableName() + " s1")
	db = db.Where("id = (?)", db.WithContext(ctx).Select("MAX(id)").Table(YamlRecord{}.TableName()+" s2").Where("s2.resource_online = 1 and s1.resource_cluster_key = s2.resource_cluster_key and s1.resource_namespace = s2.resource_namespace and s1.resource_kind = s2.resource_kind and s1.resource_name = s2.resource_name"))
	if name != "" {
		db = db.Where("resource_name like ?", "%"+name+"%")
	}
	if namespace != "" {
		db = db.Where("resource_namespace like ?", "%"+namespace+"%")
	}
	if templateName != "" {
		if hackEqualTemplateName != "" {
			db = db.Where("template_name like ? OR template_name = ?", "%"+templateName+"%", hackEqualTemplateName)
		} else {
			db = db.Where("template_name like ?", "%"+templateName+"%")
		}
	}
	if len(clusterKeys) != 0 {
		db = db.Where("resource_cluster_key in ?", clusterKeys)
	}
	if len(kinds) != 0 {
		db = db.Where("resource_kind in ?", kinds)
	}
	dbStatuses := ""
	secureOrInThreat := 0
	rateSymbol := ""
	if len(statuses) != 0 {
		for i := range statuses {
			if statuses[i] == YamlRecordRateStatusUnknown {
				dbStatuses = YamlRecordStatusInitial
			}
			if statuses[i] == YamlRecordRateStatusSecure {
				secureOrInThreat += 1
			}
			if statuses[i] == YamlRecordRateStatusInThreat {
				secureOrInThreat += 2
			}
		}
	}
	if secureOrInThreat == 3 { // secure && inThreat
		rateSymbol = "<="
	}
	if secureOrInThreat == 2 { // inThreat
		rateSymbol = "<"
	}
	if secureOrInThreat == 1 { // secure
		rateSymbol = "="
	}
	if rateSymbol != "" {
		if dbStatuses != "" {
			db = db.Where(fmt.Sprintf("success_rate %s 1 OR status = ?", rateSymbol), dbStatuses)
		} else {
			db = db.Where(fmt.Sprintf("success_rate %s 1 AND status = ?", rateSymbol), YamlRecordStatusComplete)
		}
	} else {
		if dbStatuses != "" {
			db = db.Where("status = ?", dbStatuses)
		}
	}

	if startTime != 0 {
		db = db.Where("created_at >= ?", time.UnixMilli(startTime))
	}
	if endTime != 0 {
		db = db.Where("created_at <= ?", time.UnixMilli(endTime))
	}
	return db
}

func FindYamlRecordsByIDs(ctx context.Context, db *gorm.DB, ids []int, options map[string]interface{}) ([]YamlRecord, error) {
	records := make([]YamlRecord, 0)
	db = db.WithContext(ctx)
	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err := db.Where("id in ?", ids).Find(&records).Error
	return records, err
}

func FindYamlRecordsByStatus(ctx context.Context, db *gorm.DB, taskID int, statuses []string, options map[string]interface{}) (int64, []YamlRecord, error) {
	records := make([]YamlRecord, 0)
	db = db.WithContext(ctx).Model(&YamlRecord{}).Where("task_id = ?", taskID)
	if len(statuses) != 0 {
		db = db.Where("status in ?", statuses)
	} else {
		db = db.Where("status != ?", YamlRecordStatusInitial)
	}

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindYamlRecordsByStatus count fails")
		return 0, nil, err
	}

	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err = db.Find(&records).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindYamlRecordsByStatus find fails")
		return 0, nil, err
	}

	return count, records, err
}

func FindYamlRecords(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) ([]YamlRecord, error) {
	records := make([]YamlRecord, 0)
	db = db.WithContext(ctx).Where(filter)
	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err := db.Find(&records).Error
	return records, err
}

func FirstOrCreateRecord(ctx context.Context, db *gorm.DB, record YamlRecord) (YamlRecord, error) {
	err := db.WithContext(ctx).Where(YamlRecord{
		ResourceClusterKey: record.ResourceClusterKey,
		ResourceNamespace:  record.ResourceNamespace,
		ResourceKind:       record.ResourceKind,
		ResourceName:       record.ResourceName,
		ResourceGeneration: record.ResourceGeneration,
	}).FirstOrCreate(&record).Error
	return record, err
}

func CreateYamlRecordAndNewOnline(ctx context.Context, db *gorm.DB, record YamlRecord) (YamlRecord, error) {
	// 这里有一个业务逻辑，在创建新record时，说明该资源有最新的在线版本，此时将resource_online更新到这个record上
	if err := UpdateYamlRecord(ctx, db, map[string]interface{}{
		"resource_cluster_key": record.ResourceClusterKey,
		"resource_namespace":   record.ResourceNamespace,
		"resource_kind":        record.ResourceKind,
		"resource_name":        record.ResourceName,
		"resource_online":      1,
	}, map[string]interface{}{
		"resource_online": 0,
	}); err != nil {
		return YamlRecord{}, err
	}
	record.ResourceOnline = true
	return CreateYamlRecord(ctx, db, record)
}

func CreateYamlRecord(ctx context.Context, db *gorm.DB, record YamlRecord) (YamlRecord, error) {
	return record, db.WithContext(ctx).Create(&record).Error
}

func UpdateYamlRecord(ctx context.Context, db *gorm.DB, filter map[string]interface{}, updates map[string]interface{}) error {
	return db.WithContext(ctx).Model(&YamlRecord{}).Where(filter).Updates(updates).Error
}

// UpdateYamlRecordAlreadyComplete
// task中存在之前已经扫过的资源，在创建task时会仍然标记为waiting，但并不会实际进行扫描
// 所以在实际扫描完一个子任务后，将其id之前的子任务，一并改为complete
func UpdateYamlRecordAlreadyComplete(ctx context.Context, db *gorm.DB, taskID int, recordID int) error {
	return db.WithContext(ctx).Model(&YamlRecord{}).Where("task_id = ? AND id < ? AND status = ?", taskID, recordID, YamlRecordStatusWaiting).Updates(map[string]interface{}{"status": YamlRecordStatusComplete, "updated_at": time.Now()}).Error
}

func UpdateYamlRecordByIDs(ctx context.Context, db *gorm.DB, ids []int, updates map[string]interface{}) error {
	return db.WithContext(ctx).Model(&YamlRecord{}).Where("id in ?", ids).Updates(updates).Error
}

type YamlResult struct {
	ID                 int       `json:"id"`
	ResourceClusterKey string    `json:"resource_cluster_key"`
	ResourceNamespace  string    `json:"resource_namespace"`
	ResourceKind       string    `json:"resource_kind"`
	ResourceName       string    `json:"resource_name"`
	ResourceGeneration int64     `json:"resource_generation"`
	Duration           int       `json:"duration"`
	Status             string    `json:"status"`
	Result             string    `json:"result"`
	Yaml               string    `json:"yaml"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func (YamlResult) TableName() string {
	return "ivan_iac_yaml_results"
}

func FindYamlResultsByIDs(ctx context.Context, db *gorm.DB, ids []int) ([]YamlResult, error) {
	results := make([]YamlResult, 0)
	err := db.WithContext(ctx).Where("id in ?", ids).Find(&results).Error
	return results, err
}

func FindYamlResults(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) ([]YamlResult, error) {
	results := make([]YamlResult, 0)
	db = db.WithContext(ctx)
	if resultIDs, ok := filter["result_id"]; ok {
		db = db.Where("id in ?", resultIDs)
		delete(filter, "result_id")
	}
	db = db.Where(filter)
	if order, ok := options["order"]; ok {
		db = db.Order(order)
	}
	if offset, ok := options["offset"].(int); ok {
		db = db.Offset(offset)
	}
	if limit, ok := options["limit"].(int); ok {
		db = db.Limit(limit)
	}
	err := db.Find(&results).Error
	return results, err
}

func FirstOrCreateResult(ctx context.Context, db *gorm.DB, result YamlResult) (YamlResult, error) {
	err := db.WithContext(ctx).Where(YamlResult{
		ResourceClusterKey: result.ResourceClusterKey,
		ResourceNamespace:  result.ResourceNamespace,
		ResourceKind:       result.ResourceKind,
		ResourceName:       result.ResourceName,
		ResourceGeneration: result.ResourceGeneration,
	}).FirstOrCreate(&result).Error
	return result, err
}

func CreateOrUpdateYamlResult(ctx context.Context, db *gorm.DB, result YamlResult) (YamlResult, error) {
	db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "resource_cluster_key"}, {Name: "resource_namespace"}, {Name: "resource_kind"}, {Name: "resource_name"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"duration":   result.Duration,
			"status":     result.Status,
			"result":     result.Result,
			"yaml":       result.Yaml,
			"created_at": result.CreatedAt,
			"updated_at": result.UpdatedAt,
		}),
	}).Create(&result)
	return result, db.WithContext(ctx).Create(&result).Error
}

func CreateYamlResult(ctx context.Context, db *gorm.DB, result YamlResult) (YamlResult, error) {
	return result, db.WithContext(ctx).Create(&result).Error
}

func UpdateYamlResult(ctx context.Context, db *gorm.DB, filter map[string]interface{}, updates map[string]interface{}) error {
	return db.WithContext(ctx).Model(&YamlResult{}).Where(filter).Updates(updates).Error
}

func FilterYamlResultByTemplate(ctx context.Context, db *gorm.DB, result string, templateSnapShotID int) (string, float64, error) {
	templateSnapShots, err := FindYamlTemplateSnapshots(ctx, db, map[string]interface{}{"id": templateSnapShotID}, map[string]interface{}{})
	if err != nil || len(templateSnapShots) != 1 {
		err = fmt.Errorf("FindYamlTemplateSnapshots err: %v, len: %d", err, len(templateSnapShots))
		logging.Get().Error().Err(err).Msg("FindYamlTemplateSnapshots fails")
		return "", 0, err
	}
	rules, err := FindYamlRulesByBuiltinIDs(ctx, db, templateSnapShots[0].Rules)
	if err != nil {
		err = fmt.Errorf("FindYamlRules err: %v", err)
		logging.Get().Error().Err(err).Msg("FindYamlRules fails")
		return "", 0, err
	}
	rulesMap := make(map[string]struct{})
	for i := range rules {
		rulesMap[rules[i].ThirdPartyID] = struct{}{}
	}

	flattenResults := make([]goPkgIac.FlatResult, 0)
	err = json.Unmarshal([]byte(result), &flattenResults)
	if err != nil {
		logging.Get().Error().Err(err).Msg("Unmarshal results fails")
		return "", 0, err
	}

	filterResults := make([]goPkgIac.FlatResult, 0)
	for i := range flattenResults {
		if _, ok := rulesMap[flattenResults[i].RuleID]; ok {
			filterResults = append(filterResults, flattenResults[i])
		}
	}

	bfr, err := json.Marshal(filterResults)
	if err != nil {
		logging.Get().Error().Err(err).Msg("Marshal results fails")
		return "", 0, err
	}

	return string(bfr), 1 - float64(len(filterResults))/float64(len(rules)), nil
}

func SuccessRateToRateStatus(rate float64) string {
	if rate < 1 {
		return YamlRecordRateStatusInThreat
	} else {
		return YamlRecordRateStatusSecure
	}
}

type ViewYamlConfigPeriodSchedule struct {
	Type string   `json:"type"` // type枚举为：day、week、month
	Days []string `json:"days"` // type为week时，值为星期几，星期日为0；type为month时，值为第几号，1号为1；type为day时，该字段无意义
	Time string   `json:"time"` // 时、分
}
type ViewYamlConfigTemplate struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}
type ViewYamlConfigPeriodObjectsCluster struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}
type ViewYamlConfigPeriodObjects struct {
	All      bool     `json:"all"`
	Clusters []string `json:"clusters"`
}
type ViewYamlConfig struct {
	PeriodToggle   bool                         `json:"period_toggle"`
	PeriodSchedule ViewYamlConfigPeriodSchedule `json:"period_schedule"`
	PeriodTemplate ViewYamlConfigTemplate       `json:"period_template"`
	PeriodObjects  ViewYamlConfigPeriodObjects  `json:"period_objects"`

	UpdateToggle   bool                   `json:"update_toggle"`
	UpdateTemplate ViewYamlConfigTemplate `json:"update_template"`
}

type ViewScanResultLocation struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}

type ViewYamlScanResult struct {
	SeqNo           int                    `json:"seq_no"`
	RuleID          string                 `json:"rule_id"`
	RuleName        string                 `json:"rule_name"`
	RuleDescription string                 `json:"rule_description"`
	Description     string                 `json:"description"`
	Resolution      string                 `json:"resolution"`
	Severity        string                 `json:"severity"`
	Location        ViewScanResultLocation `json:"location"`
}

type RecordToRun struct {
	Record YamlRecord
	Result YamlResult
	Yaml   []byte `json:"yaml"`
}

type ViewRule struct {
	BuiltinID   string `json:"builtin_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type ViewTask struct {
	ID           int    `json:"id"`
	ScanType     string `json:"scan_type"`
	ScheduleID   int    `json:"schedule_id"`
	TemplateID   int    `json:"template_id"`
	TemplateName string `json:"template_name"`
	Total        int    `json:"total"`
	Success      int    `json:"success"`
	Status       string `json:"status"`
	Duration     int    `json:"duration"`
	Creator      string `json:"creator"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

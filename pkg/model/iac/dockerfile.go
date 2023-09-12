package iac

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"

	"gitlab.com/security-rd/go-pkg/iac/pkg/scan"
	goPkgIac "gitlab.com/security-rd/go-pkg/iac/pkg/scan"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	DockerfileRecordStatusPass      = "pass"
	DockerfileRecordStatusBlock     = "block"
	DockerfileRecordStatusAlert     = "alert"
	DockerfileRecordStatusException = "exception"

	DockerfileRecordStatusPassCode      = 0
	DockerfileRecordStatusBlockCode     = 1
	DockerfileRecordStatusAlertCode     = 2
	DockerfileRecordStatusExceptionCode = 3

	DockerfileScanActionAlert = "alert"
	DockerfileScanActionBlock = "block"

	DockerfileResultStatusPass      = "pass"
	DockerfileResultStatusBlock     = "block"
	DockerfileResultStatusAlert     = "alert"
	DockerfileResultStatusException = "exception"
)

type DockerfileRecord struct {
	ID              int             `json:"id"`
	UUID            string          `json:"uuid"`
	PipelineName    string          `json:"pipeline_name"`
	TemplateID      int             `json:"template_id"`
	TemplateName    string          `json:"template_name"`
	FilesCount      int             `json:"files_count"`
	DockerfilePaths DockerfilePaths `json:"dockerfile_paths"`
	Status          string          `json:"status"`
	CreatedAt       time.Time       `json:"created_at"`
}

func (DockerfileRecord) TableName() string {
	return "ivan_iac_dockerfile_records"
}

func CreateDockerfileRecord(ctx context.Context, db *gorm.DB, record DockerfileRecord) (DockerfileRecord, error) {
	return record, db.WithContext(ctx).Create(&record).Error
}

func FindDockerfileRecordsByConditions(ctx context.Context, db *gorm.DB, dockerfilePath, pipelineName, templateName string, statuses []string, startTime, endTime int64, options map[string]interface{}) (int64, []DockerfileRecord, error) {
	records := make([]DockerfileRecord, 0)
	db = db.WithContext(ctx).Model(&DockerfileRecord{})
	if dockerfilePath != "" {
		db = db.Where("dockerfile_paths like ?", "%"+dockerfilePath+"%")
	}
	if pipelineName != "" {
		db = db.Where("pipeline_name like ?", "%"+pipelineName+"%")
	}
	if templateName != "" {
		db = db.Where("template_name like ?", "%"+templateName+"%")
	}
	if len(statuses) != 0 {
		db = db.Where("status in (?)", statuses)
	}
	if startTime != 0 {
		db = db.Where("created_at >= ?", time.UnixMilli(startTime))
	}
	if endTime != 0 {
		db = db.Where("created_at <= ?", time.UnixMilli(endTime))
	}

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindDockerfileRecordsByConditions count fails")
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
		logging.Get().Error().Err(err).Msg("FindDockerfileRecordsByConditions find fails")
		return 0, nil, err
	}
	return count, records, err
}

func FindDockerfileRecords(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) (int64, []DockerfileRecord, error) {
	records := make([]DockerfileRecord, 0)
	db = db.WithContext(ctx).Model(&DockerfileRecord{}).Where(filter)

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindDockerfileRecords count fails")
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
		logging.Get().Error().Err(err).Msg("FindDockerfileRecords find fails")
		return 0, nil, err
	}
	return count, records, err
}

type DockerfileResult struct {
	ID             int       `json:"id"`
	RecordID       int       `json:"record_id"`
	DockerfilePath string    `json:"dockerfile_path"`
	Dockerfile     string    `json:"dockerfile"`
	Result         string    `json:"result"`
	HitWhitelist   bool      `json:"hit_whitelist"`
	SuccessRate    float64   `json:"success_rate"`
	Status         string    `json:"status"`
	ParseError     string    `json:"parse_error"`
	Error          string    `json:"error"`
	CreatedAt      time.Time `json:"created_at"`
}

func (DockerfileResult) TableName() string {
	return "ivan_iac_dockerfile_results"
}

func CreateDockerfileResultInBatch(ctx context.Context, db *gorm.DB, results []DockerfileResult) error {
	return db.WithContext(ctx).CreateInBatches(results, 100).Error
}

func FindDockerfileResults(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) (int64, []DockerfileResult, error) {
	results := make([]DockerfileResult, 0)
	db = db.WithContext(ctx).Model(&DockerfileResult{}).Where(filter)

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindDockerfileResults count fails")
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
	err = db.Find(&results).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindDockerfileResults find fails")
		return 0, nil, err
	}
	return count, results, err
}

type DockerfileTemplate struct {
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

func (DockerfileTemplate) TableName() string {
	return "ivan_iac_dockerfile_rule_templates"
}

func CreateDockerfileTemplate(ctx context.Context, db *gorm.DB, template DockerfileTemplate) (DockerfileTemplate, error) {
	return template, db.WithContext(ctx).Create(&template).Error
}

func UpdateDockerfileTemplate(ctx context.Context, db *gorm.DB, filter map[string]interface{}, updates map[string]interface{}) error {
	return db.WithContext(ctx).Model(&DockerfileTemplate{}).Where(filter).Updates(updates).Error
}

func DeleteDockerfileTemplate(ctx context.Context, db *gorm.DB, filter map[string]interface{}) error {
	return db.WithContext(ctx).Where(filter).Delete(&DockerfileTemplate{}).Error
}

func FindDockerfileTemplates(ctx context.Context, db *gorm.DB, filter map[string]interface{}) ([]DockerfileTemplate, error) {
	templates := make([]DockerfileTemplate, 0)
	err := db.WithContext(ctx).Where(filter).Find(&templates).Error
	return templates, err
}

func FindDockerfileTemplatesByName(ctx context.Context, db *gorm.DB, name, hackEqualName string, options map[string]interface{}) (int64, []DockerfileTemplate, error) {
	templates := make([]DockerfileTemplate, 0)
	db = db.WithContext(ctx).Model(&DockerfileTemplate{}).Where("name like ?", "%"+name+"%")
	if offset, ok := options["offset"].(int); (ok && offset == 0) || hackEqualName != "" {
		db = db.Or("name = ?", hackEqualName)
	}

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindDockerfileTemplatesByName count fails")
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
		logging.Get().Error().Err(err).Msg("FindDockerfileTemplatesByName find fails")
		return 0, nil, err
	}

	return count, templates, err
}

type DockerfileTemplateSnapshot struct {
	ID          int           `json:"id"`
	TemplateID  int           `json:"template_id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Rules       TemplateRules `json:"rules"`
	Creator     string        `json:"creator"`
	Updater     string        `json:"updater"`
	Builtin     int           `json:"builtin"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

func (DockerfileTemplateSnapshot) TableName() string {
	return "ivan_iac_dockerfile_rule_template_snapshots"
}

func CreateDockerfileTemplateSnapshot(ctx context.Context, db *gorm.DB, snapshot DockerfileTemplateSnapshot) (DockerfileTemplateSnapshot, error) {
	return snapshot, db.WithContext(ctx).Create(&snapshot).Error
}

func FindDockerfileTemplateSnapshots(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) ([]DockerfileTemplateSnapshot, error) {
	templates := make([]DockerfileTemplateSnapshot, 0)
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
	err := db.Find(&templates).Error
	return templates, err
}

type DockerfileRule struct {
	ID           int    `json:"id"`
	BuiltinID    string `json:"builtin_id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Severity     string `json:"severity"`
	ThirdPartyID string `json:"third_party_id"`
}

func (DockerfileRule) TableName() string {
	return "ivan_iac_dockerfile_rules"
}

func CreateDockerfileRules(ctx context.Context, db *gorm.DB, rules []DockerfileRule) error {
	return db.WithContext(ctx).CreateInBatches(rules, 100).Error
}

func FindDockerfileRules(ctx context.Context, db *gorm.DB, filter map[string]interface{}, options map[string]interface{}) ([]DockerfileRule, error) {
	rules := make([]DockerfileRule, 0)
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

func FindDockerfileRulesByBuiltinIDs(ctx context.Context, db *gorm.DB, builtinIDs []string) ([]DockerfileRule, error) {
	rules := make([]DockerfileRule, 0)
	err := db.WithContext(ctx).Where("builtin_id in ?", builtinIDs).Find(&rules).Error
	return rules, err
}

func FindDockerfileRulesByConditions(ctx context.Context, db *gorm.DB, name string, severity []string, options map[string]interface{}) (int64, []DockerfileRule, error) {
	rules := make([]DockerfileRule, 0)
	db = db.WithContext(ctx).Model(&DockerfileRule{})
	if name != "" {
		db = db.Where("name like ?", "%"+name+"%")
	}
	if len(severity) != 0 {
		db = db.Where("severity in ?", severity)
	}

	count := int64(0)
	err := db.Count(&count).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("FindDockerfileRulesByConditions count fails")
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
		logging.Get().Error().Err(err).Msg("FindDockerfileRulesByConditions find fails")
		return 0, nil, err
	}
	return count, rules, err
}

type DockerfilePaths []string

func (t *DockerfilePaths) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("gorm.Scan failed to assert CustomKV: %v", value)
	}

	result := DockerfilePaths{}
	if len(bytes) == 0 {
		bytes = []byte("[]")
	}
	err := json.Unmarshal(bytes, &result)
	*t = result
	return err
}

func (t DockerfilePaths) Value() (driver.Value, error) {
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

type DockerfileConfig struct {
	ID        int             `json:"id"`
	Status    int             `json:"status"`
	Action    string          `json:"action"`
	WhiteList DockerfilePaths `json:"white_list"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func (DockerfileConfig) TableName() string {
	return "ivan_iac_dockerfile_configs"
}

func GetDockerfileConfig(ctx context.Context, db *gorm.DB) (DockerfileConfig, error) {
	config := DockerfileConfig{}
	err := db.WithContext(ctx).First(&config).Error
	return config, err
}

func CreateOrUpdateDockerfileConfig(ctx context.Context, db *gorm.DB, config DockerfileConfig) error {
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"status":     config.Status,
			"action":     config.Action,
			"white_list": config.WhiteList,
			"updated_at": config.UpdatedAt,
		}),
	}).Create(&config).Error
}

func CreateDockerfileConfig(ctx context.Context, db *gorm.DB, config DockerfileConfig) (DockerfileConfig, error) {
	return config, db.WithContext(ctx).Create(&config).Error
}

type DockerfilePolicy struct {
	Toggle     bool            `json:"toggle"`
	Name       string          `json:"name"`
	TemplateID int             `json:"template_id"`
	Rules      TemplateRules   `json:"rules"`
	WhiteList  DockerfilePaths `json:"white_list"`
	Action     string          `json:"action"`
}

func (p *DockerfilePolicy) GetName() string { return p.Name }

func (p *DockerfilePolicy) Check(result []scan.FlatResult) ([]scan.FlatResult, bool) {
	rulesMap := map[string]struct{}{}
	for i := range p.Rules {
		rulesMap[p.Rules[i]] = struct{}{}
	}

	results := make([]scan.FlatResult, 0)
	for i := range result {
		if _, ok := rulesMap[result[i].RuleID]; ok {
			results = append(results, result[i])
		}
	}

	return results, len(results) == 0
}

func FilterDockerfileResultByTemplate(ctx context.Context, db *gorm.DB, result string, templateSnapShotID int) (string, float64, error) {
	templateSnapShots, err := FindDockerfileTemplateSnapshots(ctx, db, map[string]interface{}{"id": templateSnapShotID}, map[string]interface{}{})
	if err != nil || len(templateSnapShots) != 1 {
		err = fmt.Errorf("FindDockerfileTemplateSnapshots err: %v, len: %d", err, len(templateSnapShots))
		logging.Get().Error().Err(err).Msg("FindDockerfileTemplateSnapshots fails")
		return "", 0, err
	}
	rules, err := FindDockerfileRulesByBuiltinIDs(ctx, db, templateSnapShots[0].Rules)
	if err != nil {
		err = fmt.Errorf("FindDockerfileRulesByBuiltinIDs err: %v", err)
		logging.Get().Error().Err(err).Msg("FindDockerfileRulesByBuiltinIDs fails")
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

type ViewDockerfileScanResult struct {
	SeqNo           int                    `json:"seq_no"`
	RuleID          string                 `json:"rule_id"`
	RuleName        string                 `json:"rule_name"`
	RuleDescription string                 `json:"rule_description"`
	Description     string                 `json:"description"`
	Resolution      string                 `json:"resolution"`
	Severity        string                 `json:"severity"`
	Location        ViewScanResultLocation `json:"location"`
}

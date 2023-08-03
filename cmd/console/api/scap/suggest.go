package scap

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
)

const (
	suggestComplianceItem    = "complianceItem"
	suggestComplianceSection = "section"
	suggestUDBCP             = "udbcp"
	suggestHostname          = "hostname"
)

var suggester map[string]SuggestProvider

func init() {
	suggester = make(map[string]SuggestProvider)
	suggester[suggestComplianceItem] = &providerComplianceItem{}
	suggester[suggestComplianceSection] = &providerComplianceSection{}
	suggester[suggestUDBCP] = &providerUDBCP{}
	suggester[suggestHostname] = &providerHostname{}
}

func GetSuggestProvider(name string) SuggestProvider {
	if p, ok := suggester[name]; ok {
		return p
	}

	return &providerBase{Kind: name}
}

// SuggestProvider interface
type SuggestProvider interface {
	FindSuggestList(ctx context.Context, db *gorm.DB, taskID, keyword string, offset, limit int) ([]*suggestItem, error)
}

type suggestItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// providerBase
type providerBase struct {
	Kind string
}

func (p providerBase) FindSuggestList(ctx context.Context, db *gorm.DB, taskID, keyword string, offset, limit int) ([]*suggestItem, error) {
	logging.Get().Info().Str("kind", p.Kind).Msg("unknown kind")
	return []*suggestItem{}, nil
}

type providerComplianceItem struct{}

func (providerComplianceItem) FindSuggestList(ctx context.Context, db *gorm.DB, taskID, keyword string, offset, limit int) ([]*suggestItem, error) {
	list := make([]*suggestItem, 0)

	db = db.WithContext(ctx).Model(&model.ScanResult{}).
		Select("policy_id AS value, policy_id AS label").
		Where("task_id = ?", taskID).Group("policy_id")
	if keyword != "" {
		db = db.Where("policy_id LIKE ?", "%"+keyword+"%")
	}

	if err := db.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		return nil, err
	}

	return list, nil
}

type providerComplianceSection struct{}

func (providerComplianceSection) FindSuggestList(ctx context.Context, db *gorm.DB, taskID, keyword string, offset, limit int) ([]*suggestItem, error) {
	list := make([]*suggestItem, 0)

	db = db.WithContext(ctx).Model(&model.ScanResult{}).
		Select("section AS value, section AS label").
		Where("task_id = ? AND section<>''", taskID).Group("section")
	if keyword != "" {
		db = db.Where("section LIKE ?", "%"+keyword+"%")
	}

	if err := db.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		return nil, err
	}

	return list, nil
}

type providerUDBCP struct{}

func (providerUDBCP) FindSuggestList(ctx context.Context, db *gorm.DB, taskID, keyword string, offset, limit int) ([]*suggestItem, error) {
	list := make([]*suggestItem, 0)

	db = db.WithContext(ctx).Model(&model.ScanResult{}).
		Select("udbcp AS value,udbcp AS label").
		Where("task_id = ? AND udbcp<>''", taskID).Group("udbcp")
	if keyword != "" {
		db = db.Where("udbcp LIKE ?", "%"+keyword+"%")
	}

	if err := db.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		return nil, err
	}

	return list, nil
}

type providerHostname struct{}

func (providerHostname) FindSuggestList(ctx context.Context, db *gorm.DB, taskID, keyword string, offset, limit int) ([]*suggestItem, error) {
	list := make([]*suggestItem, 0)

	db = db.WithContext(ctx).Model(&model.ScanNodeRecord{}).
		Select("node_name AS value, node_name AS label").
		Where("task_id = ?", taskID)
	if keyword != "" {
		db = db.Where("node_name LIKE ?", "%"+keyword+"%")
	}

	if err := db.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		return nil, err
	}

	return list, nil
}

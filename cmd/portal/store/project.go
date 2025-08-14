package store

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/security-rd/go-pkg/databases"
)

type ProjectDal interface {
	SearchProject(ctx context.Context, param model.SearchProjectParam) ([]*model.Project, int64, error)
	CreateProject(ctx context.Context, project *model.Project) error
	UpdateProject(ctx context.Context, param model.UpdateProjectParam) error
	DeleteProject(ctx context.Context, id int64) error
}

type projectStore struct {
	db *databases.RDBInstance
}

func NewProjectStore(db *databases.RDBInstance) ProjectDal {
	return &projectStore{db: db}
}

func (s *projectStore) SearchProject(ctx context.Context, param model.SearchProjectParam) ([]*model.Project, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	projects := make([]*model.Project, 0)
	db := s.db.Get().WithContext(ctx).Model(&model.Project{})
	if param.Name != "" {
		db = db.Where("name like ?", fmt.Sprintf("%%%s%%", param.Name))
	}
	if param.UserID > 0 {
		db = db.Where("user_id = ?", param.UserID)
	}
	if param.Category != "" {
		db = db.Where("category = ?", param.Category)
	}
	if param.Url != "" {
		db = db.Where("url like ?", fmt.Sprintf("%%%s%%", param.Url))
	}
	if len(param.Ids) > 0 {
		db = db.Where("id IN ?", param.Ids)
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if len(param.GitType) > 0 {
		db = db.Where("git_type IN ? ", param.GitType)
	}
	if len(param.RiskLevel) > 0 {
		db = db.Where("risk_level IN ?", param.RiskLevel)
	}
	if param.ProjectUuid != "" {
		db = db.Where("uuid = ?", param.ProjectUuid)
	}
	if param.CodesecScanStatus != "" {
		db = db.Where("codesec_scan_status = ?", param.CodesecScanStatus)
	}
	if param.SourceCheckScanStatus != "" {
		db = db.Where("source_check_scan_status = ?", param.SourceCheckScanStatus)
	}

	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = imagesecModel.AddFilter(db, param.Filter)
	if err := db.Find(&projects).Error; err != nil {
		return nil, 0, err
	}
	for i := range projects {
		projects[i].Deserialize()
	}
	return projects, cnt, nil
}

func (s *projectStore) CreateProject(ctx context.Context, project *model.Project) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	project.Serialize()
	if err := project.Check(); err != nil {
		return err
	}

	db := s.db.Get().WithContext(ctx).Create(project)

	return db.Error
}

func (s *projectStore) UpdateProject(ctx context.Context, param model.UpdateProjectParam) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if (param.ID <= 0 && param.CodesecUUID == "" && param.SourceCheckUUID == "") || len(param.Updater) == 0 {
		return nil
	}
	db := s.db.Get().WithContext(ctx).Model(&model.Project{})
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.CodesecUUID != "" {
		db = db.Where("codesec_uuid = ?", param.CodesecUUID)
	}
	if param.SourceCheckUUID != "" {
		db = db.Where("source_check_uuid = ?", param.SourceCheckUUID)
	}
	if err := db.Updates(param.Updater).Error; err != nil {
		return err
	}
	return nil
}

func (s *projectStore) DeleteProject(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(ctx).Where("id = ?", id).Delete(&model.Project{})
	return db.Error
}

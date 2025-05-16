package store

import (
	"context"
	"fmt"
	"time"

	model "gitlab.com/piccolo_su/vegeta/cmd/portal/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/security-rd/go-pkg/databases"
)

type ProjectStore interface {
	SearchProject(ctx context.Context, param model.SearchProjectParam) ([]*model.Project, int64, error)
	CreateProject(ctx context.Context, project *model.Project) error
	UpdateProject(ctx context.Context, param model.UpdateProjectParam) error
	DeleteProject(ctx context.Context, id int64) error
}

type projectStore struct {
	db *databases.RDBInstance
}

func NewProjectStore(db *databases.RDBInstance) ProjectStore {
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
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.GitType != "" {
		db = db.Where("git_type = ?", param.GitType)
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
	if param.ID <= 0 || len(param.Updater) == 0 {
		return nil
	}
	db := s.db.Get().WithContext(ctx).Model(&model.Project{}).Where("id = ?", param.ID).Updates(param.Updater)
	return db.Error
}

func (s *projectStore) DeleteProject(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := s.db.Get().WithContext(ctx).Where("id = ?", id).Delete(&model.Project{})
	return db.Error
}

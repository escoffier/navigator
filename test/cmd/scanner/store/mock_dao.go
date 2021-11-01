package store

import (
	"context"
	"errors"
	"fmt"
	"github.com/mattn/go-colorable"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	logg "log"
	"time"
)

type MockScannerOrm struct {
	psql *rdbtools.GormWrapper
}

func NewPostgresDb(host, port, username, password string) (*MockScannerOrm, *gorm.DB, error) {
	connectString := fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=disable", username, password, host, port)
	newLogger := logger.New(
		logg.New(colorable.NewColorableStdout(), "\r\n", logg.LstdFlags),
		logger.Config{
			SlowThreshold: time.Second,
			LogLevel:      logger.Info,
			Colorful:      true,
		},
	)
	db, err := rdbtools.GormWrapperOpen(1*time.Minute, func() (*gorm.DB, error) {
		return gorm.Open(postgres.Open(connectString), &gorm.Config{Logger: newLogger})
	})
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("open postgres err:%v", err))
	}
	sqlDB, err := db.Get().DB()
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("get db err:%v", err))
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(30)
	sqlDB.SetConnMaxLifetime(time.Hour)
	mso := &MockScannerOrm{
		psql: db,
	}
	return mso, db.Get(), nil
}

func (s *MockScannerOrm) InsertTask(ctx context.Context, t model.Task) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	tmp := model.Task{}
	res := s.psql.Get().WithContext(ctx).Where("id= ?", t.ID).First(&tmp)
	if res.Error != nil {
		err := s.psql.Get().Create(&t).Error
		return t.ID, err
	}

	err := s.psql.Get().Model(tmp).Updates(&t).Error
	return tmp.ID, err
}

func (s *MockScannerOrm) InsertSubTask(ctx context.Context, t model.SubTask) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	tmp := model.SubTask{}
	res := s.psql.Get().WithContext(ctx).Where("id= ?", t.ID).First(&tmp)
	if res.Error != nil {
		err := s.psql.Get().Create(&t).Error
		return t.ID, err
	}

	err := s.psql.Get().Model(tmp).Updates(&t).Error
	return tmp.ID, err
}

func (s *MockScannerOrm) GetTask(ctx context.Context, filter *model.Filter) ([]model.Task, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.Task)).WithContext(ctx)
	res := make([]model.Task, 0)
	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (s *MockScannerOrm) GetSubTask(ctx context.Context, filter *model.Filter) ([]model.SubTask, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*5)
	defer cancelFunc()
	db := s.psql.Get().Model(new(model.SubTask)).WithContext(ctx)
	res := make([]model.SubTask, 0)
	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

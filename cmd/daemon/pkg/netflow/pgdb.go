package netflow

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PgDb struct {
	Db *gorm.DB
}

func NewConnPgDB(host string, user string, password string, dbname string, port string) (*PgDb, error) {
	// TODO: timescaledb deployment requires ssl mode on, but maybe we don't need it?...
	dns := fmt.Sprintf("host=%s user=%s password=%s DB.name=%s port=%s sslmode=disable", host, user, password, dbname, port)
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dns,
		PreferSimpleProtocol: true,
	}), &gorm.Config{})

	if err != nil {
		return nil, err
	}

	pg := PgDb{
		Db: db,
	}

	return &pg, nil
}

func (pg *PgDb) InitMigration() error {
	return pg.Db.AutoMigrate(&model.K8sNetToplgy{})
}

func (pg *PgDb) SaveNetTopology(ctx context.Context, data *model.K8sNetToplgy) error {
	count, err := pg.GetK8sNetInfoCount(ctx, data.TableName(), data.Uuid)
	if err != nil {
		return err
	}

	if count > 0 {
		return pg.UpdateActiveTime(context.Background(), data.Uuid)
	}

	return pg.Db.WithContext(ctx).Create(data).Error
}

func (pg *PgDb) GetTimeoutK8sNetData(tx context.Context, t time.Time) ([]model.K8sNetToplgy, error) {
	var ret []model.K8sNetToplgy
	var tbn model.K8sNetToplgy
	err := pg.Db.WithContext(tx).Table(tbn.TableName()).Where("updated_at < ?", t).Scan(&ret).Error
	if err != nil {
		return nil, fmt.Errorf("scan db with time failed, %v", err)
	}
	return ret, nil
}

func (pg *PgDb) GetK8sNetInfoCount(tx context.Context, tbName string, uuid uint32) (int64, error) {
	var count int64
	err := pg.Db.WithContext(tx).Table(tbName).Where("uuid = ?", uuid).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("query net data by uuid, %v", err)
	}
	return count, nil
}

func (pg *PgDb) DeleteK8sNetTimeoutInfo(tx context.Context, t time.Time) error {
	err := pg.Db.WithContext(tx).Where("updated_at < ?", t).Delete(&model.K8sNetToplgy{}).Error
	if err != nil {
		return fmt.Errorf("query net data by uuid, %v", err)
	}
	return nil
}

func (pg *PgDb) UpdateActiveTime(tx context.Context, uuid uint32) error {
	err := pg.Db.WithContext(tx).Where("uuid = ?", uuid).Updates(&model.K8sNetToplgy{Status: 1, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("upate time failed, uuid = %v, %v.", uuid, err)
	}
	return err
}

func (pg *PgDb) UpdateStatus(tx context.Context, t time.Time, status int) error {
	return pg.Db.WithContext(tx).Where("updated_at < ?", t).Updates(&model.K8sNetToplgy{Status: status}).Error
}

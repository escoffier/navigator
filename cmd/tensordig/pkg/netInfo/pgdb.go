package netInfo

import (
	"context"
	"fmt"
	"hash/fnv"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type K8sResData struct {
	Cluster   string `json:"cluster" gorm:"primaryKey;type:varchar(100)"`
	Name      string `json:"name" gorm:"primaryKey;type:varchar(100)"`
	Kind      string `json:"kind" gorm:"primaryKey;type:varchar(100)"`
	Namespace string `json:"namespace" gorm:"primaryKey;type:varchar(100)"`
}

type K8sNetToplgy struct {
	Uuid      uint32     `json:"uuid" gorm:"uuid"`
	SrcRes    K8sResData `gorm:"embedded;embeddedPrefix:src_"`
	DstRes    K8sResData `gorm:"embedded;embeddedPrefix:dst_"`
	Status    int        `json:"status" gorm:"status"`
	DstPort   int        `json:"dst_port", gorm:"dst_port;type:integer"`
	Proto     uint8      `json:"proto", gorm:"proto"`
	CreatedAt time.Time  `json:"created_at" gorm:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" gorm:"updated_at"`
}

var NetSvcTbName = "tensor_network_flows"

type PgDb struct {
	db *gorm.DB
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
		db: db,
	}

	return &pg, nil
}

func (pg *PgDb) InitMigration() error {
	return pg.db.Table(NetSvcTbName).AutoMigrate(&K8sNetToplgy{})
}

func (pg *PgDb) SaveNetTopology(ctx context.Context, data *K8sNetToplgy) error {
	count, err := pg.GetK8sNetInfoCount(ctx, NetSvcTbName, data.Uuid)
	if err != nil {
		return err
	}

	if count > 0 {
		return pg.UpdateActiveTime(context.Background(), data.Uuid)
	}

	return pg.db.WithContext(ctx).Table(NetSvcTbName).Create(data).Error
}

func (pg *PgDb) GetTimeoutK8sNetData(tx context.Context, t time.Time) ([]K8sNetToplgy, error) {
	var ret []K8sNetToplgy
	err := pg.db.WithContext(tx).Table(NetSvcTbName).Where("updated_at < ?", t).Scan(&ret).Error
	if err != nil {
		return nil, fmt.Errorf("scan db with time failed, %v", err)
	}
	return ret, nil
}

func (pg *PgDb) GetK8sNetInfoCount(tx context.Context, tbName string, uuid uint32) (int64, error) {
	var count int64
	err := pg.db.WithContext(tx).Table(tbName).Where("uuid = ?", uuid).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("query net data by uuid, %v", err)
	}
	return count, nil
}

func (pg *PgDb) DeleteK8sNetTimeoutInfo(tx context.Context, t time.Time) error {
	err := pg.db.WithContext(tx).Table(NetSvcTbName).Where("updated_at < ?", t).Delete(&K8sNetToplgy{}).Error
	if err != nil {
		return fmt.Errorf("query net data by uuid, %v", err)
	}
	return nil
}

func (pg *PgDb) UpdateActiveTime(tx context.Context, uuid uint32) error {
	err := pg.db.WithContext(tx).Table(NetSvcTbName+" as tb").Where("tb.Uuid = ?", uuid).Update("status", 1).Update("updated_at", time.Now()).Error
	if err != nil {
		log.Errorf("upate time failed, uuid = %v, %v.", uuid, err)
	}
	return err
}

func (pg *PgDb) UpdateStatus(tx context.Context, t time.Time, status int) error {
	return pg.db.WithContext(tx).Table(NetSvcTbName+" as tb").Where("updated_at < ?", t).Update("status", status).Error
}

func (knt *K8sNetToplgy) CreateUuid() {
	src := &knt.SrcRes
	dst := &knt.DstRes
	value := fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v,%v,%v",
		src.Cluster, src.Kind, src.Name, src.Namespace,
		dst.Cluster, dst.Kind, dst.Name, dst.Namespace, knt.DstPort)

	//log.Infof("create uuid by value : %s", value)
	h := fnv.New32a()
	h.Write([]byte(value))
	knt.Uuid = h.Sum32()
}

func (krd *K8sResData) ToString() string {
	return fmt.Sprintf("Cluster : %s, name : %s, kind : %s, namespace : %s.", krd.Cluster, krd.Name, krd.Kind, krd.Namespace)
}

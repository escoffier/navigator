package apiinfo

import (
	"context"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"strconv"
	"strings"
	"time"
)

const ApiSubject = "security-api"

var pgConn *rdbtools.GormWrapper

func Process(msg *stan.Msg) {
	info := ApiInfo{}
	proto.Unmarshal(msg.Data, &info)
	logging.GetLogger().Debug().Msgf("received msg: %+v", info)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	path := info.Path
	params := ""
	if strings.Contains(info.Path, "?") {
		ss := strings.SplitN(info.Path, "?", 2)
		if len(ss) == 2 {
			path = ss[0]
			params = ss[1]
		}
	}

	tensorApi := model.TensorApi{
		ID:          0,
		Cluster:     info.ClusterKey,
		Namespace:   info.Namespace,
		PodName:     info.PodName,
		IP:          info.RemoteIp,
		Port:        strconv.Itoa(int(info.RemotePort)),
		Path:        path,
		Params:      params,
		Scheme:      info.Scheme,
		ContentType: info.ContentType,
		Method:      info.Method,
		Resource:    info.OwnerName,
		Kind:        info.OwnerKind,
	}

	err := UpsertApiInfo(ctx, pgConn, &tensorApi)
	if err != nil {
		logging.GetLogger().Err(err).Msg("save api info err")
		return
	}
}

func InitPG() error {
	//PgDsn := postgresOpts.PostgresConnectionString
	PgDsn := os.Getenv("PG_ADDR")
	var err error
	pgConn, err = rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
		db, err := gorm.Open(postgres.Open(PgDsn), &gorm.Config{})
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
			return nil, err
		}
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.SetMaxOpenConns(30)
			sqlDB.SetMaxIdleConns(5)
			sqlDB.SetConnMaxLifetime(time.Hour)
		}
		return db, nil
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("Init postgre error")
		return err
	}
	return nil
}

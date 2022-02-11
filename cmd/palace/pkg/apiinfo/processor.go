package apiinfo

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"google.golang.org/protobuf/proto"
)

const APISubject = "security-api"

var pgConn *rdbtools.GormWrapper

func Process(msg *stan.Msg) {
	info := ApiInfo{}
	err := proto.Unmarshal(msg.Data, &info)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("proto unmarshal err. data: %s", string(msg.Data))
	}
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

	tensorAPI := model.TensorApi{
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

	err = UpsertApiInfo(ctx, pgConn, &tensorAPI)
	if err != nil {
		logging.GetLogger().Err(err).Msg("save api info err")
		return
	}
}

func InitDB(pg *rdbtools.GormWrapper) error {
	pgConn = pg
	return nil
}

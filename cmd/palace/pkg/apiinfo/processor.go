package apiinfo

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/proto"
)

const APISubject = "security-api"

var rdb *databases.RDBInstance

func Process(msg kafka.Message) {
	info := ApiInfo{}
	err := proto.Unmarshal(msg.Value, &info)
	if err != nil {
		logging.Get().Err(err).Str("data", string(msg.Value)).Msg("proto unmarshal err.")
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

	err = UpsertAPIInfo(ctx, rdb, &tensorAPI)
	if err != nil {
		logging.Get().Err(err).Msg("save api info err")
		return
	}
}

func InitDB(pg *databases.RDBInstance) error {
	rdb = pg
	return nil
}

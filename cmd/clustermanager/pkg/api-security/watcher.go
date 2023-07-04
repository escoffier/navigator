package apisecurity

import (
	"context"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/api-security/security"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gorm.io/gorm/clause"
)

type ApiWatcher struct {
	consumer mq.Reader
	topic    string
	groupID  string
	db       *databases.RDBInstance
}

var onDupUpdatedColsForApiInfo = []string{
	"updated_at",
	"ip",
	"port",
	"params",
	"content_type",
}

func NewWatcher(reader mq.Reader, topic, groupID string, rdb *databases.RDBInstance) *ApiWatcher {
	return &ApiWatcher{
		consumer: reader,
		topic:    topic,
		groupID:  groupID,
		db:       rdb,
	}
}

func (w *ApiWatcher) Run(stopCh <-chan struct{}) {
	w.consumer.Subscribe(w.topic, w.groupID, w.process)
	<-stopCh
}

func (w *ApiWatcher) process(ctx context.Context, message kafka.Message) error {

	apiInfo := &security.ApiInfo{}
	err := proto.Unmarshal(message.Value, apiInfo)
	if err != nil {
		return err
	}

	api := &model.TensorApi{
		ID:          int64(util.GenerateUUID(apiInfo.ClusterKey, apiInfo.Namespace, apiInfo.OwnerKind, apiInfo.OwnerName, apiInfo.Path, apiInfo.Method)),
		Cluster:     apiInfo.ClusterKey,
		Resource:    apiInfo.OwnerName,
		Kind:        apiInfo.OwnerKind,
		Namespace:   apiInfo.Namespace,
		PodName:     apiInfo.PodName,
		IP:          apiInfo.RemoteIp,
		Port:        strconv.Itoa(int(apiInfo.RemotePort)),
		Path:        apiInfo.Path,
		Params:      "",
		Scheme:      apiInfo.Scheme,
		ContentType: apiInfo.ContentType,
		Method:      apiInfo.Method,
		BaseInfo: model.BaseInfo{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	err = w.db.Get().WithContext(ctx).Model(api).Clauses(
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForApiInfo),
		},
	).Create(api).Error
	if err != nil {
		logging.Get().Err(err).Msgf("failed to insert api: %s", apiInfo.String())
		return err
	}

	return nil
}

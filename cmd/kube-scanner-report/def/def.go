package def

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	ErrTaskConflict = fmt.Errorf("task conflict")
	ErrNoRecord     = fmt.Errorf("no record")
)

type TaskManager interface {
	CreateKubeHunterRecord(ctx context.Context, cluster, uuid, username string) (*model.KubeHunterRecord, error)
	DealExpireRecords(ctx context.Context, nowTime time.Time) error
	GetLatestCompleteRecord(ctx context.Context, cluster string) (*model.KubeHunterRecord, error)
	UpdateRecord(ctx context.Context, uuid string, status uint8, metaInfo []byte) error
	CheckInProgress(ctx context.Context, cluster string) (bool, error)
}

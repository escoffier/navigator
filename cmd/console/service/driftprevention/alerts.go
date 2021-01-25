package driftprevention

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	DriftPreventionreasonChecksumMismatch = "ChecksumMismatch"
	DriftPreventionReasonNotInWhitelist   = "NotInWhitelist"

	DriftPreventionActionNotified = "Notified"
	DriftPreventionActionBlocked  = "Blocked"
)

type DriftPreventionAlertRequest struct {
	Podname       string `json:"podname"`
	Filepath      string `json:"filepath"`
	CRC32Expected uint32 `json:"crc32Expected,omitempty""`
	CRC32Actual   uint32 `json:"crc32Actual,omitempty"`
	Reason        string `json:"reason"`
	Action        string `json:"action"`
	Syscall       string `json:"syscall"`
}

type DriftPreventionService struct {
	mongo *mongo.Database
}

func NewDriftPreventionService(mongodb *mongo.Database) *DriftPreventionService {
	return &DriftPreventionService{
		mongo: mongodb,
	}
}

func (dp *DriftPreventionService) RaiseAlert(ctx context.Context, rawAlert *DriftPreventionAlertRequest) error {
	sev := redclair.SeverityHigh
	newAlert := model.Alert{
		ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
		AlertKind:   string(model.AlertKindDriftPrevention),
		Timestamp:   time.Now(),
		Severity:    string(sev),
		SeverityInt: util.SeverityToInt(string(sev)),
		MessageEn:   "Drift Prevention detected suspicious activity",
		MessageZh:   "Drift Prevention检测到可疑活动",
		DriftPreventionAlert: &model.DriftPreventionAlert{
			AffectedPod:   rawAlert.Podname,
			Filepath:      rawAlert.Filepath,
			CRC32Expected: rawAlert.CRC32Expected,
			CRC32Actual:   rawAlert.CRC32Actual,
			Syscall:       rawAlert.Syscall,
			Reason:        rawAlert.Reason,
			Action:        rawAlert.Action,
		},
	}

	_, err := dp.mongo.Collection(model.AlertsCollection.String()).InsertOne(ctx, newAlert)
	if err != nil {
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Failed to insert alert %+v: %w", newAlert, err))
	}

	return nil
}

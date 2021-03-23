package driftprevention

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	alertsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/alert"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/mgo.v2/bson"
)

const (
	DriftPreventionreasonChecksumMismatch = "ChecksumMismatch"
	DriftPreventionReasonNotInWhitelist   = "NotInWhitelist"

	DriftPreventionActionNotified = "Notified"
	DriftPreventionActionBlocked  = "Blocked"

	alertPollInterval = time.Second * 30
	alertPollTimeout  = time.Second * 15
	cacheWriteTTLSec  = 24 * 60 * 60
	cacheReadTTLSec   = 60 * 60
)

type DriftPreventionAlertRequest struct {
	PodNamespace  string `json:"podnamespace"`
	Podname       string `json:"podname"`
	PodUID        string `json:"poduid"`
	Filepath      string `json:"filepath"`
	CRC32Expected uint32 `json:"crc32Expected,omitempty""`
	CRC32Actual   uint32 `json:"crc32Actual,omitempty"`
	Reason        string `json:"reason"`
	Action        string `json:"action"`
	Syscall       string `json:"syscall"`
}

type DriftPreventionService struct {
	mongo     *mongo.Database
	aggrCache *alertsSvc.AlertAggrCache
	mutex     *sync.Mutex
}

func NewDriftPreventionService(mongodb *mongo.Database) *DriftPreventionService {
	return &DriftPreventionService{
		mongo:     mongodb,
		aggrCache: alertsSvc.NewAlertAggrCache(10, cacheReadTTLSec, cacheWriteTTLSec),
		mutex:     &sync.Mutex{},
	}
}

func isAlertContextAlmostTheSame(newCtx model.AlertContext, oldCtx model.AlertContext) bool {
	if newCtx.PodUID == oldCtx.PodUID {
		delta := (newCtx.Timestamp.Unix() - oldCtx.Timestamp.Unix())
		return delta > -60 && delta < 60
	}
	return false
}

func (dp *DriftPreventionService) RaiseAlert(ctx context.Context, rawAlert *DriftPreventionAlertRequest) error {
	sev := redclair.SeverityHigh

	var services []string
	var namespace string
	var svcOK bool
	cluster := "default"
	// by only podName we cannot get service.
	saService, saOk := assetsSvc.GetServiceAssetsService()
	if saOk && saService.IsClusterSynced(cluster) {
		svcs, ns, ok := saService.GetServiceInfoOfPod(cluster, rawAlert.PodUID)
		if ok {
			services = svcs
			namespace = ns
			svcOK = true
		}
	}
	if !svcOK {
		services = []string{"unknown"}
		namespace = "unknown"
	}

	// TODO: send timestamp in alert
	timestamp := time.Now()

	alertCtx := model.AlertContext{
		// ContainerID: rawAlert.ContainerID,
		PodName:   rawAlert.Podname,
		PodUID:    rawAlert.PodUID,
		Timestamp: timestamp.Local(), // use local time; should do it in frontend; FIXME
	}

	dp.mutex.Lock()
	defer dp.mutex.Unlock()

	for _, service := range services {
		aggrKey := fmt.Sprintf("%s:%s:%s:%s:%s", cluster, namespace, service, rawAlert.Action, rawAlert.Filepath) // cached by cluster:namespace:service:action:filepath
		idPtr, cacheExist := dp.aggrCache.GetByKey(aggrKey, timestamp.Unix())
		var alert *model.Alert
		if cacheExist && idPtr != nil {
			logging.GetLogger().Info().Msgf("alerts aggr cache hits with key: %s:%s and got value: %v", rawAlert.Action, rawAlert.Filepath, *idPtr)
			filter := bson.M{"_id": *idPtr}

			queryResult := dp.mongo.Collection(model.AlertsCollection.String()).FindOne(ctx, filter)

			if queryResult.Err() == nil {
				alert = new(model.Alert)
				decErr := queryResult.Decode(alert)
				if decErr != nil {
					logging.GetLogger().Err(decErr).Msgf("query alerts collection id %v err", *idPtr)
					alert = nil
				}
			} else {
				logging.GetLogger().Err(queryResult.Err()).Msgf("query alerts collection id %v err", *idPtr)
			}
		}

		if alert != nil { // There are aggregated Alert instance.
			// if this history exists, don't update
			existed := false
			for _, histCtx := range alert.Histories {
				if isAlertContextAlmostTheSame(alertCtx, histCtx) {
					existed = true
					break
				}
			}

			if !existed {
				alert.Timestamp = timestamp
				if alert.DriftPreventionAlert == nil {
					alert.DriftPreventionAlert = &model.DriftPreventionAlert{
						AffectedPod:   rawAlert.Podname,
						Filepath:      rawAlert.Filepath,
						CRC32Expected: rawAlert.CRC32Expected,
						CRC32Actual:   rawAlert.CRC32Actual,
						Syscall:       rawAlert.Syscall,
						Reason:        rawAlert.Reason,
						Action:        rawAlert.Action,
					}
				}
				alert.Severity = string(sev)
				alert.SeverityInt = util.SeverityToInt(string(sev))
				alert.MessageEn = "Drift Prevention detected suspicious activity"
				alert.MessageZh = "Drift Prevention检测到可疑活动"
				alert.Service = service
				alert.Namespace = namespace
				alert.Cluster = cluster

				alert.HistoricisedTimestamp = timestamp
				alert.Histories = append(alert.Histories, alertCtx)
				filter := bson.M{"_id": *idPtr}
				// delete the previous one and insert into the new one. So the Mongo _id will be updated after merging.
				alert.ID = primitive.NewObjectIDFromTimestamp(time.Now())
				_, err := dp.mongo.Collection(model.AlertsCollection.String()).DeleteOne(ctx, filter)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("Failed to delete drift prevention alert: %w", err)
				}

				_, err = dp.mongo.Collection(model.AlertsCollection.String()).InsertOne(ctx, alert)
				if err != nil {
					return NewMongoError(http.StatusInternalServerError,
						fmt.Errorf("Failed to insert drift prevention alert: %w", err))
				} else {
					earlist := timestamp
					if len(alert.Histories) > 0 {
						earlist = alert.Histories[0].Timestamp
					}
					dp.aggrCache.Put(aggrKey, alert.ID, earlist.Unix(), timestamp.Unix()) // set the previous write timestamp and read timestap
				}
			}
		} else {
			newAlert := model.Alert{
				ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
				AlertKind:   string(model.AlertKindDriftPrevention),
				Timestamp:   time.Now(),
				Severity:    string(sev),
				SeverityInt: util.SeverityToInt(string(sev)),
				MessageEn:   "Drift Prevention detected suspicious activity",
				MessageZh:   "Drift Prevention检测到可疑活动",
				Service:     service,
				Namespace:   namespace,
				Cluster:     cluster,
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

			newAlert.HistoricisedTimestamp = timestamp
			newAlert.Histories = []model.AlertContext{
				alertCtx,
			}
			now := time.Now()
			newAlert.HistoricisedTimestamp = now
			_, err := dp.mongo.Collection(model.AlertsCollection.String()).InsertOne(ctx, newAlert)
			if err != nil {
				return NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Failed to insert drift prevention alert: %w", err))
			} else {
				// put them to cache
				dp.aggrCache.Put(aggrKey, newAlert.ID, timestamp.Unix(), timestamp.Unix())
			}
		}
	}

	return nil
}

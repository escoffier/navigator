package seccomp

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	alertsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/alert"
	assetsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/assets"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/mgo.v2/bson"
)

const (
	SeccompTestingPhase = "Test"
	SeccompProdPhase    = "Prod"

	SeccompActionNotified = "Notified"
	SeccompActionBlocked  = "Blocked"

	alertPollInterval = time.Second * 30
	alertPollTimeout  = time.Second * 15
	cacheWriteTTLSec  = 24 * 60 * 60
	cacheReadTTLSec   = 60 * 60
)

type SeccompProfileService struct {
	mongo     *mongo.Database
	aggrCache *alertsSvc.AlertAggrCache
	mutex     *sync.Mutex
}

func NewSeccompProfileService(mongodb *mongo.Database) *SeccompProfileService {
	return &SeccompProfileService{
		mongo:     mongodb,
		aggrCache: alertsSvc.NewAlertAggrCache(10, cacheReadTTLSec, cacheWriteTTLSec),
		mutex:     &sync.Mutex{},
	}
}

func (sp *SeccompProfileService) RaiseAlert(ctx context.Context, rawAlert *model.SeccompProfileAlertRequest) error {
	sev := redclair.SeverityHigh

	var services []string
	var namespace string
	var svcOK bool
	cluster := "default"
	// by only podName we cannot get service.
	saService, saOk := assetsSvc.GetServiceAssetsService()
	if saOk && saService.IsClusterSynced(cluster) {
		sinfo, ok := saService.GetServiceInfoOfPod(cluster, rawAlert.PodUID)
		if ok && sinfo != nil {
			svcs := sinfo.Services()
			if len(svcs) > 0 {
				services = svcs
			} else {
				services = append(services, sinfo.OwnerReferenceName())
			}
			namespace = sinfo.Namespace
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
		ContainerID: rawAlert.ContainerID,
		PodName:     rawAlert.Podname,
		PodUID:      rawAlert.PodUID,
		Timestamp:   timestamp.Local(), // use local time; should do it in frontend; FIXME
	}

	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	for _, service := range services {
		aggrKey := fmt.Sprintf("%s:%s:%s:%s:%s", cluster, namespace, service, rawAlert.Action, rawAlert.Syscall) // cached by cluster:namespace:service:action:syscall
		idPtr, cacheExist := sp.aggrCache.GetByKey(aggrKey, timestamp.Unix())
		var alert *model.Alert
		if cacheExist && idPtr != nil {
			logging.GetLogger().Info().Msgf("alerts aggr cache hits with key: %s:%s and got value: %v", rawAlert.Action, rawAlert.Syscall, *idPtr)
			filter := bson.M{"_id": *idPtr}

			queryResult := sp.mongo.Collection(model.AlertsCollection.String()).FindOne(ctx, filter)

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
				if alert.SeccompProfileAlert == nil {
					alert.SeccompProfileAlert = &model.SeccompProfileAlert{
						AffectedPod: rawAlert.Podname,
						Phase:       rawAlert.Phase,
						Syscall:     rawAlert.Syscall,
						Action:      rawAlert.Action,
					}
				}
				alert.Severity = string(sev)
				alert.SeverityInt = util.SeverityToInt(string(sev))
				alert.MessageEn = "Seccomp profile detected suspicious activity"
				alert.MessageZh = "Seccomp profile检测到可疑活动"
				alert.Service = service
				alert.Namespace = namespace
				alert.Cluster = cluster

				alert.HistoricisedTimestamp = timestamp
				alert.Histories = append(alert.Histories, alertCtx)
				filter := bson.M{"_id": *idPtr}
				update := bson.M{"$set": alert}
				_, err := sp.mongo.Collection(model.AlertsCollection.String()).UpdateOne(ctx, filter, update)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("Failed to update seccomp alert: %w", err)
				} else {
					earlist := timestamp
					if len(alert.Histories) > 0 {
						earlist = alert.Histories[0].Timestamp
					}
					sp.aggrCache.Put(aggrKey, alert.ID, earlist.Unix(), timestamp.Unix()) // set the previous write timestamp and read timestap
				}
			}
		} else {
			newAlert := model.Alert{
				ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
				AlertKind:   string(model.AlertKindSeccompProfile),
				Timestamp:   time.Now(),
				Severity:    string(sev),
				SeverityInt: util.SeverityToInt(string(sev)),
				MessageEn:   "Seccomp profile detected suspicious activity",
				MessageZh:   "Seccomp profile检测到可疑活动",
				Service:     service,
				Namespace:   namespace,
				Cluster:     cluster,
				SeccompProfileAlert: &model.SeccompProfileAlert{
					AffectedPod: rawAlert.Podname,
					Phase:       rawAlert.Phase,
					Syscall:     rawAlert.Syscall,
					Action:      rawAlert.Action,
				},
			}

			newAlert.HistoricisedTimestamp = timestamp
			newAlert.Histories = []model.AlertContext{
				alertCtx,
			}
			now := time.Now()
			newAlert.HistoricisedTimestamp = now
			_, err := sp.mongo.Collection(model.AlertsCollection.String()).InsertOne(ctx, newAlert)
			if err != nil {
				return NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Failed to insert seccomp alert: %w", err))
			} else {
				// put them to cache
				sp.aggrCache.Put(aggrKey, newAlert.ID, timestamp.Unix(), timestamp.Unix())
			}
		}
	}

	return nil
}

func isAlertContextAlmostTheSame(newCtx model.AlertContext, oldCtx model.AlertContext) bool {
	if newCtx.PodUID == oldCtx.PodUID && newCtx.ContainerID == oldCtx.ContainerID {
		delta := (newCtx.Timestamp.Unix() - oldCtx.Timestamp.Unix())
		return delta > -60 && delta < 60
	}
	return false
}

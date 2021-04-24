package falco

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	alertsSvc "gitlab.com/piccolo_su/vegeta/cmd/console/service/alert"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/mgo.v2/bson"
)

const (
	alertPollInterval = time.Second * 30
	alertPollTimeout  = time.Second * 15
	cacheWriteTTLSec  = 24 * 60 * 60
	cacheReadTTLSec   = 60 * 60
)

type FalcoAlertRequest struct {
	Output       string                 `json:"output"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time""`
	OutputFields map[string]interface{} `json:"output_fields"`
	Proprity     string                 `json:"priority"`
}

type FalcoService struct {
	mongo     *mongotools.DatabaseWrapper
	aggrCache *alertsSvc.AlertAggrCache
	mutex     *sync.Mutex
}

func NewFalcoService(mongodb *mongotools.DatabaseWrapper) *FalcoService {
	return &FalcoService{
		mongo:     mongodb,
		aggrCache: alertsSvc.NewAlertAggrCache(10, cacheReadTTLSec, cacheWriteTTLSec),
		mutex:     &sync.Mutex{},
	}
}

func (f *FalcoService) RaiseAlert(ctx context.Context, rawAlert *FalcoAlertRequest) error {
	sev := redclair.SeverityHigh

	container := ""
	if val, ok := rawAlert.OutputFields["container.id"]; ok {
		if val != nil {
			container = val.(string)
		}
	}

	if val, ok := rawAlert.OutputFields["container_id"]; ok {
		if val != nil {
			container = val.(string)
		}
	}

	image := ""
	if val, ok := rawAlert.OutputFields["image"]; ok {
		if val != nil {
			image = val.(string)
		}
	}

	user := ""
	if val, ok := rawAlert.OutputFields["user.name"]; ok {
		if val != nil {
			user = val.(string)
		}
	}

	namespace := ""
	if val, ok := rawAlert.OutputFields["k8s.ns.name"]; ok {
		if val != nil {
			namespace = val.(string)
		}
	}

	pod := ""
	if val, ok := rawAlert.OutputFields["k8s.pod.name"]; ok {
		if val != nil {
			pod = val.(string)
		}
	}

	command := ""
	if val, ok := rawAlert.OutputFields["proc.cmdline"]; ok {
		if val != nil {
			command = val.(string)
		}
	}

	syscallName := ""
	if val, ok := rawAlert.OutputFields["syscall.type"]; ok {
		if val != nil {
			syscallName = val.(string)
		}
	}

	outDict := dealOutputStr(rawAlert.Output)

	zhMsg := ""
	ruleType := ""
	if outDict != nil {
		if val, ok := outDict["zh_msg"]; ok {
			if len(val) > 0 {
				zhMsg = val
			}
		}
		if val, ok := outDict["rule_type"]; ok {
			if len(val) > 0 {
				ruleType = val
			}
		}
		if len(command) <= 0 {
			if val, ok := outDict["cmdline"]; ok {
				if len(val) > 0 && val != "<NA>" {
					command = val
				}
			}
		}
	}

	if len(rawAlert.Proprity) > 0 {
		sev = falcoPriority2sev(rawAlert.Proprity)
	}

	cluster := "default"
	// TODO: Falco doesn't send pod uid - need to get context based on the available information
	services := []string{"unknown"}

	// TODO: send timestamp in alert
	timestamp := rawAlert.Time

	ruleStr := rawAlert.Rule

	if strings.HasPrefix(ruleStr, "Falco") {
		return nil
	}

	alertCtx := model.AlertContext{
		ContainerID: container,
		PodName:     pod,
		PodUID:      "",
		Timestamp:   timestamp.Local(), // use local time; should do it in frontend; FIXME
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()
	for _, service := range services {
		aggrKey := fmt.Sprintf("%s:%s:%s:%s", cluster, namespace, service, rawAlert.Rule) // cached by cluster:namespace:service:action:rule
		idPtr, cacheExist := f.aggrCache.GetByKey(aggrKey, timestamp.Unix())
		var alert *model.Alert
		if cacheExist && idPtr != nil {
			logging.GetLogger().Info().Msgf("alerts aggr cache hits with key: %s and got value: %v", rawAlert.Rule, *idPtr)
			filter := bson.M{"_id": *idPtr}

			queryResult := f.mongo.Get().Collection(model.AlertsCollection.String()).FindOne(ctx, filter)

			if queryResult.Err() == nil {
				alert = &model.Alert{}
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
				if alert.FalcoAlert == nil {
					alert.FalcoAlert = &model.FalcoAlert{
						AffectedPod: pod,
						User:        user,
						Container:   container,
						Command:     command,
						Image:       image,
						Syscall:     syscallName,
						RuleType:    "",
					}
				}
				alert.Severity = string(sev)
				alert.SeverityInt = util.SeverityToInt(string(sev))
				alert.MessageEn = rawAlert.Rule
				alert.MessageZh = rawAlert.Rule
				if len(zhMsg) > 0 {
					alert.MessageZh = zhMsg
				}
				if len(ruleType) > 0 {
					alert.MessageZh = ruleTypeEn2Cn(ruleType) + ": " + alert.MessageZh
					alert.MessageEn = ruleType + ": " + alert.MessageEn
					alert.FalcoAlert.RuleType = ruleType + ": " + rawAlert.Rule
				}
				alert.Service = service
				alert.Namespace = namespace
				alert.Cluster = cluster

				alert.HistoricisedTimestamp = timestamp
				alert.Histories = append(alert.Histories, alertCtx)
				filter := bson.M{"_id": *idPtr}
				update := bson.M{"$set": alert}

				_, err := f.mongo.Get().Collection(model.AlertsCollection.String()).UpdateOne(ctx, filter, update)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("Failed to update falco alert: %w", err)
				} else {
					earlist := timestamp
					if len(alert.Histories) > 0 {
						earlist = alert.Histories[0].Timestamp
					}
					f.aggrCache.Put(aggrKey, alert.ID, earlist.Unix(), timestamp.Unix()) // set the previous write timestamp and read timestap
				}
			}
		} else {
			newAlert := model.Alert{
				ID:          primitive.NewObjectIDFromTimestamp(time.Now()),
				AlertKind:   string(model.AlertKindFalco),
				Timestamp:   time.Now(),
				Severity:    string(sev),
				SeverityInt: util.SeverityToInt(string(sev)),
				MessageEn:   rawAlert.Rule,
				MessageZh:   rawAlert.Rule,
				Service:     service,
				Namespace:   namespace,
				Cluster:     cluster,
				FalcoAlert: &model.FalcoAlert{
					AffectedPod: pod,
					User:        user,
					Container:   container,
					Command:     command,
					Image:       image,
					Syscall:     syscallName,
					RuleType:    "",
				},
			}
			if len(zhMsg) > 0 {
				newAlert.MessageZh = zhMsg
			}
			if len(ruleType) > 0 {
				newAlert.MessageZh = ruleTypeEn2Cn(ruleType) + ": " + newAlert.MessageZh
				newAlert.MessageEn = ruleType + ": " + newAlert.MessageEn
				newAlert.FalcoAlert.RuleType = ruleType + ": " + rawAlert.Rule
			}
			newAlert.HistoricisedTimestamp = timestamp
			newAlert.Histories = []model.AlertContext{
				alertCtx,
			}
			now := time.Now()
			newAlert.HistoricisedTimestamp = now
			_, err := f.mongo.Get().Collection(model.AlertsCollection.String()).InsertOne(ctx, newAlert)
			if err != nil {
				return NewMongoError(http.StatusInternalServerError,
					fmt.Errorf("Failed to insert falco alert: %w", err))
			} else {
				// put them to cache
				f.aggrCache.Put(aggrKey, newAlert.ID, timestamp.Unix(), timestamp.Unix())
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

func dealOutputStr(outputStr string) map[string]string {
	if len(outputStr) <= 0 {
		return nil
	}

	startIndex := strings.Index(outputStr, "=")
	endIndex := strings.LastIndex(outputStr, ")")

	if startIndex < 0 || endIndex < 0 {
		return nil
	}

	for ; startIndex >= 0; startIndex-- {
		if outputStr[startIndex] == '(' {
			break
		}
	}
	tmpStr := outputStr[startIndex+1 : endIndex]
	tmpList := strings.Split(tmpStr, ",")

	retMap := make(map[string]string)
	for _, item := range tmpList {
		keyIndex := strings.Index(item, "=")
		k := item[0:keyIndex]
		v := item[keyIndex+1:]
		retMap[k] = v
	}
	return retMap
}

func falcoPriority2sev(priority string) string {
	if len(priority) <= 0 {
		return ""
	}
	//folco rules: https://falco.org/docs/rules/#rules
	switch strings.ToLower(priority) {
	case "debug":
		return redclair.SeverityNegligible
	case "informational":
		return redclair.SeverityLow
	case "notice":
		return redclair.SeverityLow
	case "warning":
		return redclair.SeverityMedium
	case "error":
		return redclair.SeverityMedium
	case "critical":
		return redclair.SeverityHigh
	case "alert":
		return redclair.SeverityHigh
	case "emergency":
		return redclair.SeverityCritical
	default:
		return redclair.SeverityUnknown
	}
	return ""
}

func ruleTypeEn2Cn(typeRuleStr string) string {
	if len(typeRuleStr) <= 0 {
		return ""
	}
	switch strings.ToLower(typeRuleStr) {
	case "execution":
		return "命令执行"
	case "persistence":
		return "后门维持"
	case "privilege escalation":
		return "权限提升"
	case "defense evasion":
		return "检测避免"
	case "credential access":
		return "凭证获取"
	case "discovery":
		return "内网信息获取"
	case "lateral movement":
		return "横向移动"
	case "exfiltration":
		return "数据泄露"
	default:
		return "未知"
	}
	return "未知"
}

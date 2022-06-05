package kubemonitor

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	pkg "gitlab.com/piccolo_su/vegeta/pkg/kubemonitor"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc/status"
	yaml "gopkg.in/yaml.v2"
)

const (
	eventsCategory   = "kubeMonitor"
	eventsCategoryCN = "集群风险监控"
	eventsModule     = "ContainerSecurity"
	eventsModuleCN   = "容器安全"
)

var (
	rules    []*pkg.RiskyRoleItem
	parseErr error

	defaultResourceRules = []pkg.ResourceMonitorRule{
		pkg.ResourceRiskyCapsRule{},
		pkg.ResourceRiskyVolumeRule{},
		pkg.ResourceWithPrivContainerRule{},
	}
)

func init() {
	if err := parseRules(); err != nil {
		logging.Get().Err(err).Msg("parse rules error for kubemonitor")
	}
}

type Service struct {
	eventsCenterCli pb.EventsCenterCollectionServiceClient
	monitor         *pkg.KubeRiskyMonitor
	myNamespace     string

	registerOK int32
	dupCache   *DupCache
}

func parseRules() error {
	parseErr = yaml.Unmarshal([]byte(rulesDatastring), &rules)
	if parseErr != nil {
		logging.Get().Err(parseErr).Msg("parse kubemonitor rules error")
	}
	return parseErr
}
func NewService() (*Service, error) {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	monitor, err := pkg.NewKubeRiskMonitor(pkg.Configuration{
		RBRules:       rules,
		ResourceRules: defaultResourceRules,
	}, pkg.NewMemStorage)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		monitor:     monitor,
		myNamespace: namespace,
		dupCache:    newDupCache(24 * time.Hour),
	}
	svc.asyncRiskMonitor()
	return svc, nil
}

func (s *Service) RiskMonitor() *pkg.KubeRiskyMonitor {
	return s.monitor
}

func getDescriptionForRole(rawRule *pkg.RiskyRoleItem, lang, kind string) string {
	cnt := ""
	switch lang {
	case "zh":
		cnt = rawRule.Metadata.Description.RiskCN
	case "en":
		cnt = rawRule.Metadata.Description.Risk
	default:
		cnt = rawRule.Metadata.Description.Risk
	}
	return fmt.Sprintf("%s: %s", kind, cnt)
}

func getEventsRuleName(kind, ruleName string) string {
	return fmt.Sprintf("%s: %s", kind, ruleName)
}

func getSeverity(rawRule *pkg.RiskyRoleItem) uint32 {
	switch rawRule.Metadata.Priority {
	case pkg.PriorityCritical:
		return 10
	case pkg.PriorityHigh:
		return 6
	case pkg.PriorityMedium:
		return 4
	case pkg.PriorityLow:
		return 2
	case pkg.PriorityNone:
		return 0
	default:
		return 1
	}

}

func (s *Service) newDetectionRuleForResRule(raw pkg.ResourceMonitorRule) *pb.DetectionRule {
	rule := new(pb.DetectionRule)
	rule.Name = raw.RuleName()
	rule.Description = raw.Description()["en"]
	rule.Module = eventsModule
	rule.Category = eventsCategory
	rule.Severity = raw.Severity()
	rule.MultiLanguage = map[string]*pb.MultiLanguageValue{
		"description": {
			ValueHash: map[string]string{
				"zh": raw.Description()["zh"],
				"en": raw.Description()["en"],
			},
		},
		"category": {
			ValueHash: map[string]string{
				"zh": eventsCategoryCN,
				"en": eventsCategory,
			},
		},
		"module": {
			ValueHash: map[string]string{
				"zh": eventsModuleCN,
				"en": eventsModule,
			},
		},
	}
	for _, kv := range raw.KVs() {
		zhVal := kv.ValueMulti["zh"]
		if zhVal == "" {
			zhVal = kv.DefaultValue
		}
		enVal := kv.ValueMulti["en"]
		if enVal == "" {
			enVal = kv.DefaultValue
		}
		rule.CustomKV = append(rule.CustomKV, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"zh": {Key: kv.KeyMulti["zh"], Value: zhVal},
				"en": {Key: kv.KeyMulti["en"], Value: enVal},
			},
		})
	}
	return rule
}
func (s *Service) newDetectionRule(rawRule *pkg.RiskyRoleItem) []*pb.DetectionRule {
	rules := make([]*pb.DetectionRule, 0, 2)
	roleRule := pb.DetectionRule{}
	roleRule.Description = getDescriptionForRole(rawRule, "en", "role")
	roleRule.Name = pkg.GetRuleNameFromRBRule(rawRule, "role")
	roleRule.Module = eventsModule
	roleRule.Category = eventsCategory
	roleRule.Severity = getSeverity(rawRule)
	roleRule.MultiLanguage = map[string]*pb.MultiLanguageValue{
		"description": {
			ValueHash: map[string]string{
				"zh": getDescriptionForRole(rawRule, "zh", "role"),
				"en": getDescriptionForRole(rawRule, "en", "role"),
			},
		},
		"category": {
			ValueHash: map[string]string{
				"zh": eventsCategoryCN,
				"en": eventsCategory,
			},
		},
		"module": {
			ValueHash: map[string]string{
				"zh": eventsModuleCN,
				"en": eventsModule,
			},
		},
	}
	if len(rawRule.Metadata.Description.Example) > 0 {
		roleRule.CustomKV = append(roleRule.CustomKV, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"zh": {Key: "样例", Value: rawRule.Metadata.Description.Example},
				"en": {Key: "Exmaple", Value: rawRule.Metadata.Description.Example},
			},
		})
	}
	if len(rawRule.Metadata.Description.Verb) > 0 {
		roleRule.CustomKV = append(roleRule.CustomKV, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"zh": {Key: "动作", Value: rawRule.Metadata.Description.Verb},
				"en": {Key: "Verb", Value: rawRule.Metadata.Description.Verb},
			},
		})
	}
	if len(rawRule.Metadata.Description.Resources) > 0 {
		roleRule.CustomKV = append(roleRule.CustomKV, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"zh": {Key: "资源", Value: rawRule.Metadata.Description.Resources},
				"en": {Key: "Resources", Value: rawRule.Metadata.Description.Resources},
			},
		})
	}
	rules = append(rules, &roleRule)

	// nolint
	croleRule := roleRule
	croleRule.Name = pkg.GetRuleNameFromRBRule(rawRule, "clusterRole")
	croleRule.Description = getDescriptionForRole(rawRule, "en", "role")
	croleRule.MultiLanguage = map[string]*pb.MultiLanguageValue{
		"description": {
			ValueHash: map[string]string{
				"zh": getDescriptionForRole(rawRule, "zh", "clusterRole"),
				"en": getDescriptionForRole(rawRule, "en", "clusterRole"),
			},
		},
		"category": {
			ValueHash: map[string]string{
				"zh": eventsCategoryCN,
				"en": eventsCategory,
			},
		},
		"module": {
			ValueHash: map[string]string{
				"zh": eventsModuleCN,
				"en": eventsModule,
			},
		},
	}

	rules = append(rules, &croleRule)
	return rules
}

func (s *Service) setRegisterOK() {
	atomic.StoreInt32(&s.registerOK, 1)
}

func (s *Service) isRegisterOK() bool {
	return atomic.LoadInt32(&s.registerOK) == 1
}

func uuid(evt *pkg.KubeMonitorEvent, now time.Time) uint64 {
	bs := evt.Identity()

	key := fmt.Sprintf("%s-%d", bs, now.UnixNano())
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return h.Sum64()
}

func getEventTargetID(name string, kind string) string {
	return fmt.Sprintf("%s (%s)", name, kind)
}

func (s *Service) newEvtCenterReq(ctx context.Context, evt *pkg.KubeMonitorEvent) *pb.SendNotificationReq {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()

	req := new(pb.SendNotificationReq)
	req.RuleKey = new(pb.RuleKey)
	req.RuleKey.Module = eventsModule
	req.RuleKey.Category = eventsCategory
	req.RuleKey.Name = evt.RuleName

	now := time.Now()
	req.Timestamp = now.Unix()
	req.UUID = uuid(evt, now)
	req.NotifyContext = new(pb.Context)
	req.NotifyContext.Cluster = evt.ClusterKey
	req.NotifyContext.Namespace = evt.TargetObject.Namespace
	req.NotifyContext.ServiceID = strings.Join([]string{evt.TargetObject.Kind, evt.TargetObject.Name}, "/")
	req.NotifyContext.CustomKV = make([]*pb.MultiLanguageKV, len(evt.ContextKVs))

	for i, kv := range evt.ContextKVs {
		mkv := new(pb.MultiLanguageKV)
		req.NotifyContext.CustomKV[i] = mkv
		mkv.KVHash = make(map[string]*pb.KV, 2)
		if len(kv.KeyMulti) > 0 {
			for lang, key := range kv.KeyMulti {
				v, exist := kv.ValueMulti[lang]
				if !exist {
					v = kv.DefaultValue
				}
				mkv.KVHash[lang] = &pb.KV{Key: key, Value: v}
			}
		} else {
			mkv.KVHash["en"] = &pb.KV{Key: kv.Key, Value: kv.DefaultValue}
			mkv.KVHash["zh"] = &pb.KV{Key: kv.Key, Value: kv.DefaultValue}
		}
	}

	return req
}

func (s *Service) sendNotifToEventsCenter(ctx context.Context, req *pb.SendNotificationReq) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()

	oneCtx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()
	_, err := s.eventsCenterCli.SendNotification(oneCtx, req)
	if err != nil {
		logging.Get().Err(err).Msgf("send notification error. req: %+v", req)
		return err
	}
	return nil
}
func (s *Service) handleMonitorEvent(ctx context.Context, evt *pkg.KubeMonitorEvent) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()

	if s.dupCache.checkDuplicate(evt) {
		logging.Get().Info().Str("event id", evt.Identity()).Msg("find duplicated. canceled")
		return nil
	}
	if evt.TargetObject.Namespace == s.myNamespace || evt.TargetObject.Namespace == "kube-system" {
		return nil
	}
	if (evt.TargetObject.Kind == "role" || evt.TargetObject.Kind == "clusterRole") && strings.Index(evt.TargetObject.Name, "system:") == 0 {
		return nil
	}

	ecReq := s.newEvtCenterReq(ctx, evt)

	ecErr := s.sendNotifToEventsCenter(ctx, ecReq)
	if ecErr == nil {
		s.dupCache.addEvent(evt)
	}
	return nil
}

func (s *Service) asyncRiskMonitor() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		ecenterColCli, eclientErr := echelper.NewGRPCClientFromEnv()
		for eclientErr != nil {
			ecenterColCli, eclientErr = echelper.NewGRPCClientFromEnv()
			if eclientErr != nil {
				logging.Get().Err(eclientErr).Msg("init events center error")
				time.Sleep(1 * time.Second)
			} else {
				break
			}
		}
		s.eventsCenterCli = ecenterColCli

		err := s.doRegisterEventsCenterRules(context.Background())
		if err != nil {
			logging.Get().Err(err).Msg("register event center rules not all ok. will retry...")
			s.asyncRegisterEventsCenterRules()
		}

		for evt := range s.monitor.OutputChannel() {
			if err := s.handleMonitorEvent(context.Background(), evt); err != nil {
				logging.Get().Err(err).Msgf("handle monitor event error. event: %+v", evt)
			}
		}
	}()
}

func (s *Service) asyncRegisterEventsCenterRules() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic when registering eventsCenter: %v. stack: %s", r, debug.Stack())
			}
		}()

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		stop := false
		for !stop {
			for range ticker.C {
				if err := s.doRegisterEventsCenterRules(context.Background()); err == nil {
					stop = true
				} else {
					logging.Get().Err(err).Msg("register event center rules not all ok. will retry...")
				}
			}
		}
	}()

}
func (s *Service) doRegisterEventsCenterRules(ctx context.Context) error {
	if s.isRegisterOK() {
		return nil
	}

	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic when registerint eventsCenter: %v. stack: %s", r, debug.Stack())
		}
	}()

	allSuccess := true
	allRules := make([]*pb.DetectionRule, 0, 50)
	for _, resRule := range defaultResourceRules {
		resDRule := s.newDetectionRuleForResRule(resRule)
		allRules = append(allRules, resDRule)
	}

	for _, rule := range rules {
		drules := s.newDetectionRule(rule)
		for _, drule := range drules {
			allRules = append(allRules, drule)
		}
	}

	for _, r := range allRules {
		func(detectionRule *pb.DetectionRule) {
			oneCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			var clientErr error
			err := util.RetryWithBackoff(oneCtx, func() error {
				_, err := s.eventsCenterCli.AddDetectionRule(ctx, &pb.AddDetectionRuleReq{
					Rule: detectionRule,
				})
				status, ok := status.FromError(err)
				if ok && status != nil {
					if status.Code() >= 400 && status.Code() < 500 {
						// 4xx stop retry
						clientErr = err
						return nil
					}
				}
				return err
			})
			if clientErr != nil {
				err = clientErr
			}
			if err != nil {
				logging.Get().Err(err).Msgf("add rule for eventsCenter error. data: %+v", detectionRule)
				allSuccess = false
			}
		}(r)
	}

	if allSuccess {
		s.setRegisterOK()
		return nil
	} else {
		return errors.New("not all success")
	}
}

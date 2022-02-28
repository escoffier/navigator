package kubemonitor

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"runtime/debug"
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
)

func init() {
	if err := parseRules(); err != nil {
		logging.Get().Err(err).Msg("parse rules error for kubemonitor")
	}
}

type Service struct {
	eventsCenterCli pb.EventsCenterCollectionServiceClient
	monitor         *pkg.KubeRiskyMonitor

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
	monitor, err := pkg.NewKubeRiskMonitor(rules, pkg.NewMemStorage)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		monitor:  monitor,
		dupCache: newDupCache(24 * time.Hour),
	}
	svc.asyncRiskMonitor()
	return svc, nil
}

func (s *Service) RiskMonitor() *pkg.KubeRiskyMonitor {
	return s.monitor
}

func getDescriptionForRole(rawRule *pkg.RiskyRoleItem, lang string) string {
	cnt := ""
	switch lang {
	case "zh":
		cnt = rawRule.Metadata.Description.RiskCN
	case "en":
		cnt = rawRule.Metadata.Description.Risk
	default:
		cnt = rawRule.Metadata.Description.Risk
	}
	name := "role"
	return fmt.Sprintf("%s: %s", name, cnt)
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
func (s *Service) newDetectionRule(rawRule *pkg.RiskyRoleItem) []*pb.DetectionRule {
	rules := make([]*pb.DetectionRule, 0, 2)
	roleRule := pb.DetectionRule{}
	roleRule.Description = getDescriptionForRole(rawRule, "en")
	roleRule.Name = getEventsRuleName(string(pkg.KindRole), rawRule.Metadata.Name)
	roleRule.Module = eventsModule
	roleRule.Category = eventsCategory
	roleRule.Severity = getSeverity(rawRule)
	roleRule.MultiLanguage = map[string]*pb.MultiLanguageValue{
		"description": {
			ValueHash: map[string]string{
				"zh": getDescriptionForRole(rawRule, "zh"),
				"en": getDescriptionForRole(rawRule, "en"),
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
	croleRule.Name = getEventsRuleName(string(pkg.KindClusterRole), rawRule.Metadata.Name)
	rules = append(rules, &croleRule)
	return rules
}

func (s *Service) setRegisterOK() {
	atomic.StoreInt32(&s.registerOK, 1)
}

func (s *Service) isRegisterOK() bool {
	return atomic.LoadInt32(&s.registerOK) == 1
}

func uuid(ruleName string, evt pkg.KubeMonitorEvent, now time.Time) uint64 {
	bs := getEvtID(evt, ruleName)

	h := fnv.New64a()
	_, _ = h.Write(bs)
	return h.Sum64()
}

func getEventTargetID(roleName string, kind string) string {
	return fmt.Sprintf("%s (%s)", roleName, kind)
}
func (s *Service) newNotifReq(ctx context.Context, evt pkg.KubeMonitorEvent, rule *pkg.RiskyRoleItem) *pb.SendNotificationReq {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()
	req := new(pb.SendNotificationReq)
	req.RuleKey = new(pb.RuleKey)
	req.RuleKey.Module = eventsModule
	req.RuleKey.Category = eventsCategory
	req.RuleKey.Name = getEventsRuleName(string(evt.Kind), rule.Metadata.Name)

	now := time.Now()
	req.Timestamp = now.Unix()
	req.UUID = uuid(req.RuleKey.Name, evt, now)
	req.NotifyContext = new(pb.Context)
	req.NotifyContext.Cluster = evt.Cluster

	switch evt.Kind {
	case pkg.KindRole:
		req.NotifyContext.Namespace = evt.TargetRole.Namespace
		req.NotifyContext.ServiceID = getEventTargetID(evt.TargetRole.Name, string(evt.Kind))
		req.NotifyContext.CustomKV = append(req.NotifyContext.CustomKV,
			&pb.MultiLanguageKV{
				KVHash: map[string]*pb.KV{
					"zh": {
						Key:   "Role名称",
						Value: evt.TargetRole.Name,
					},
					"en": {
						Key:   "Role Name",
						Value: evt.TargetRole.Name,
					},
				},
			},
			&pb.MultiLanguageKV{
				KVHash: map[string]*pb.KV{
					"zh": {
						Key:   "Role创建时间",
						Value: evt.TargetRole.CreationTimestamp.Local().String(),
					},
					"en": {
						Key:   "Role CreateTime",
						Value: evt.TargetRole.CreationTimestamp.Local().String(),
					},
				},
			},
		)
	case pkg.KindClusterRole:
		req.NotifyContext.Namespace = "-"
		req.NotifyContext.ServiceID = getEventTargetID(evt.TargetClusterRole.Name, string(evt.Kind))
		req.NotifyContext.CustomKV = append(req.NotifyContext.CustomKV,
			&pb.MultiLanguageKV{
				KVHash: map[string]*pb.KV{
					"zh": {
						Key:   "ClusterRole名称",
						Value: evt.TargetClusterRole.Name,
					},
					"en": {
						Key:   "ClusterRole Name",
						Value: evt.TargetClusterRole.Name,
					},
				},
			},
			&pb.MultiLanguageKV{
				KVHash: map[string]*pb.KV{
					"zh": {
						Key:   "ClusterRole创建时间",
						Value: evt.TargetClusterRole.CreationTimestamp.Local().String(),
					},
					"en": {
						Key:   "ClusterRole CreateTime",
						Value: evt.TargetClusterRole.CreationTimestamp.Local().String(),
					},
				},
			},
		)

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
func (s *Service) handleMonitorEvent(ctx context.Context, evt pkg.KubeMonitorEvent) error {

	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()

	for _, riskRule := range evt.RiskyItems {
		if s.dupCache.checkDuplicate(evt, riskRule.Metadata.Name) {
			// find duplicates
			continue
		}
		ecReq := s.newNotifReq(ctx, evt, riskRule)
		ecErr := s.sendNotifToEventsCenter(ctx, ecReq)
		if ecErr == nil {
			s.dupCache.addEvent(evt, riskRule.Metadata.Name)
		}
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
	for _, rule := range rules {
		drules := s.newDetectionRule(rule)
		for _, drule := range drules {
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
			}(drule)

		}

	}
	if allSuccess {
		s.setRegisterOK()
		return nil
	} else {
		return errors.New("not all success")
	}
}

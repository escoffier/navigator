package holmes

import (
	"context"
	"encoding/base64"
	"errors"
	"math/rand"
	"os"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mozart"
	"gitlab.com/security-rd/go-pkg/cryption"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
	"scm.tensorsecurity.cn/tensorsecurity-rd/falcosider/manager"
)

const (
	currentEngineLargeVersion = 2 // 随holmes版本升级
)

var (
	filteredOutRulesSet = map[string]struct{}{
		"Falco internal: syscall event drop": {},
	}

	filteredOutFields = []string{
		model.FieldK8sNsName,
		model.FieldK8sPodName,
		model.FieldPodUID,
		model.FieldEvtTime,
	}
	engineGrpcPath string
	debugMode      bool
)

func init() {
	dm := os.Getenv("DEBUG_MODE")
	if dm == "1" || dm == "true" {
		debugMode = true
	}
}

type EngineStreamConfig struct {
	CtrlServerUrl  string
	UnixSocketPath string
	MyNodeName     string
	MyNamespace    string
	RulesDirPath   string
}

func NewEngineStreamConfig() EngineStreamConfig {
	return EngineStreamConfig{
		CtrlServerUrl:  "http://tensorsec-clustermanager:8000/",
		UnixSocketPath: "unix:///var/run/holmes-engine/engine.sock",
		MyNodeName:     "-",
		MyNamespace:    "tensorsec",
		RulesDirPath:   "/var/run/holmes-engine/rules",
	}
}

func (c *EngineStreamConfig) WithCtrlServerURL(url string) *EngineStreamConfig {
	c.CtrlServerUrl = url
	return c
}
func (c *EngineStreamConfig) WithUnixSocketPath(path string) *EngineStreamConfig {
	c.UnixSocketPath = path
	return c
}
func (c *EngineStreamConfig) WithMyNodeName(nodeName string) *EngineStreamConfig {
	c.MyNodeName = nodeName
	return c
}
func (c *EngineStreamConfig) WithRulesDirPath(dir string) *EngineStreamConfig {
	c.RulesDirPath = dir
	return c
}
func (c *EngineStreamConfig) WithMyNamespace(ns string) *EngineStreamConfig {
	c.MyNamespace = ns
	return c
}

type EngineStreamHandler struct {
	config EngineStreamConfig // immutable

	engineManager *manager.EngineManager
	cm            *k8s.ClusterInfoManager
	containerInfo nodeinfo.ContainerInfoManager
	podResInfo    *nodeinfo.PodResInfo
	palaceHandler *palace.Palace
	mozart        *mozart.Engine

	currentRulesVersion int64
	currentConfigVal    *atomic.Pointer[ruleConfig]
}

type ruleConfig struct {
	rulesConfig []*pb.RuleConfig
	version     int64
}

func NewEventsStreamHandler(config EngineStreamConfig, cm *k8s.ClusterInfoManager, containerInfo nodeinfo.ContainerInfoManager, podResInfo *nodeinfo.PodResInfo, palaceHandler *palace.Palace, mozartEngine *mozart.Engine) *EngineStreamHandler {
	h := &EngineStreamHandler{
		config: config,

		engineManager:    manager.NewEngineManager(config.RulesDirPath, config.UnixSocketPath, config.MyNamespace),
		cm:               cm,
		containerInfo:    containerInfo,
		podResInfo:       podResInfo,
		palaceHandler:    palaceHandler,
		mozart:           mozartEngine,
		currentConfigVal: new(atomic.Pointer[ruleConfig]),
	}
	h.setRulesConfig(nil, 0)
	return h
}

func toConfigsArr(data *model.LatestATTCKRuleInfo) []*pb.RuleConfig {
	configs := make([]*pb.RuleConfig, 0, len(data.ClosedRules))
	for _, ruleKey := range data.ClosedRules {
		configs = append(configs, &pb.RuleConfig{
			RuleKey:  ruleKey,
			Disabled: true,
		})
	}
	return configs
}
func (ec *EngineStreamHandler) setRulesConfig(configs []*pb.RuleConfig, version int64) {
	ec.currentConfigVal.Store(&ruleConfig{
		rulesConfig: configs,
		version:     version,
	})
}
func (ec *EngineStreamHandler) setCurrentRulesVersion(v int64) {
	atomic.StoreInt64(&ec.currentRulesVersion, v)
}
func (ec *EngineStreamHandler) getCurrentRulesVersion() int64 {
	return atomic.LoadInt64(&ec.currentRulesVersion)
}

func (ec *EngineStreamHandler) getOwnerInfo(podName, namespace string) (*nodeinfo.Resource, string, bool) {
	res, exist := ec.podResInfo.GetPod(namespace, podName)
	if exist && res != nil {
		return res, namespace, true
	}
	return nil, "", false
}

type eventItem struct {
	data       *outputs.Response
	clusterKey string
}

func (ec *EngineStreamHandler) saveToDir(data []byte, version int64) error {
	filePath := manager.GetStaticRuleTHRFilePath(ec.config.RulesDirPath, strconv.FormatInt(version, 10))
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (ec *EngineStreamHandler) asyncLoad() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("panic: %v", r)
			}
		}()

		time.Sleep(time.Duration(rand.Int63n(5000)) * time.Millisecond)
		for {
			if err := ec.engineReloads(context.Background()); err != nil {
				logging.Get().Err(err).Msg("reload error")
			}
			time.Sleep(20*time.Second + time.Duration(rand.Int63n(10000))*time.Millisecond)
		}
	}()
}

func (ec *EngineStreamHandler) doReloadingMozart(ctx context.Context, reloadReq *pb.ReloadRequest, rulesBytes []byte, rulesChanged, configChanged bool) error {
	newV := reloadReq.StaticVersion + ";" + reloadReq.SConfigVersion
	disabledFalcoM := make(map[string]*pb.RuleConfig)
	rules := make([]mozart.Rule, 0, 150)
	var err error

	if rulesChanged {
		_, decodedRuleBytes, err := manager.DoRulesDecode(rulesBytes)
		if err != nil {
			logging.Get().Error().Err(err).Str("version", reloadReq.StaticVersion).Msg("rules data mozart decode fails")
			return err
		}
		// todo: 配置修改的时候也应该改
		rules, err = ec.mozart.LoadFromRuleBytes(ctx, decodedRuleBytes)
		if err != nil {
			logging.Get().Error().Err(err).Str("version", reloadReq.StaticVersion).Msg("rules data mozart loads fails")
			return err
		}

		dM, err := extractDisabledRulesFromRules(ctx, decodedRuleBytes)
		if err != nil {
			logging.Get().Error().Err(err).Str("version", reloadReq.StaticVersion).Msg("extractDisabledRulesFromRules from ruleBytes fails")
			return err
		}
		for k := range dM {
			disabledFalcoM[k] = &pb.RuleConfig{Disabled: true, RuleKey: k}
		}

		err = ec.mozart.UpdateRules(mozart.RuleUpdateOperationAdd, newV, rules)
		if err != nil {
			logging.Get().Error().Err(err).Msg("update mozart rules fails")
			return err
		}
	}

	if configChanged {
		enabledFalcoM := make(map[string]struct{})
		disabledMozartM := make(map[string]struct{})
		for _, ruleConf := range reloadReq.SRuleConfigs {
			if ruleConf.Disabled {
				disabledMozartM[ruleConf.RuleKey] = struct{}{}
			}
		}

		// 数据没有变，读现有规则，如果没有现有规则，则报错
		if !rulesChanged {
			var ok bool
			rules, ok = ec.mozart.GetActiveRules()
			if !ok {
				logging.Get().Warn().Err(err).Str("active version", ec.mozart.GetActiveRulesVersion()).Msg("mozart GetActiveRules fails")
				return errors.New("get active rules failed")
			}
		}
		// 获得开启的falco规则
		for i := range rules {
			if _, ok := disabledMozartM[rules[i].Name]; !ok {
				for k := range rules[i].Steps {
					if rules[i].Steps[k].Name != "checkRelatedExists" {
						continue
					}
					if params, ok := rules[i].Steps[k].OriginParams.([]string); ok {
						enabledFalcoM[params[0]] = struct{}{}
					}
				}
			}
		}
		// 获得关闭的falco规则
		// 操作mozart规则的开关
		for i := range rules {
			if _, ok := disabledMozartM[rules[i].Name]; ok {
				rules[i].Enabled = false
				if rules[i].Type == "basic" {
					disabledFalcoM[rules[i].Name] = &pb.RuleConfig{RuleKey: rules[i].Name, Disabled: true}
				}
				for k := range rules[i].Steps {
					if rules[i].Steps[k].Name != "checkRelatedExists" {
						continue
					}
					if params, ok := rules[i].Steps[k].OriginParams.([]string); ok {
						if _, ok := enabledFalcoM[params[0]]; !ok {
							disabledFalcoM[params[0]] = &pb.RuleConfig{RuleKey: params[0], Disabled: true}
						}
					}
				}
			} else {
				rules[i].Enabled = true
			}
		}
		err = ec.mozart.UpdateRules(mozart.RuleUpdateOperationAdd, newV, rules)
		if err != nil {
			logging.Get().Error().Err(err).Msg("update mozart rules fails")
			return err
		}
	}

	ruleConfigs := make([]*pb.RuleConfig, 0, len(disabledFalcoM))
	for _, v := range disabledFalcoM {
		ruleConfigs = append(ruleConfigs, v)
	}
	reloadReq.SRuleConfigs = ruleConfigs

	// 同步更新engine，并等待结果
	err = ec.engineManager.ReloadEngine(context.Background(), reloadReq)
	if err != nil {
		logging.Get().Err(err).Str("sversion", reloadReq.StaticVersion).Msg("reload error")

		merr := ec.mozart.UpdateRules(mozart.RuleUpdateOperationDel, newV, nil)
		if merr != nil {
			logging.Get().Error().Err(merr).Msg("update mozart rules fails")
			return merr
		}
		return err
	} else {
		logging.Get().Info().Str("sversion", reloadReq.StaticVersion).Msg("reload ok")
		err = ec.mozart.UpdateRules(mozart.RuleUpdateOperationDel, ec.mozart.GetActiveRulesVersion(), nil)
		if err != nil {
			logging.Get().Error().Err(err).Msg("update mozart rules fails")
			return err
		}
		ec.mozart.SetActiveRulesVersion(newV)
	}

	return nil
}

func (ec *EngineStreamHandler) engineReloads(ctx context.Context) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("panic: %v", r)
		}
	}()

	rulesInfo, err := dal.LoadAttackRules(context.Background(), ec.config.CtrlServerUrl, currentEngineLargeVersion, ec.getCurrentRulesVersion(), ec.currentConfigVal.Load().version)
	if err != nil {
		return err
	}
	rulesChanged, configsChanged := false, false
	sversion := ec.getCurrentRulesVersion()
	reloadReq := new(pb.ReloadRequest)
	if rulesInfo.LatestDataVersion > ec.getCurrentRulesVersion() && rulesInfo.DataChanged {
		if debugMode {
			// DEBUG start
			dec, err := base64.StdEncoding.DecodeString(rulesInfo.Data)
			if err == nil {
				header, rulesContext, _, _ := cryption.ReadRulesData(dec)
				logging.Get().Info().Uints16("version", header.Version[:]).Msg("DEBUG updated rules")
				ec.saveToDir(rulesContext, 9999999)
			}
			// DEBUG end
		}

		if err := ec.saveToDir([]byte(rulesInfo.Data), rulesInfo.LatestDataVersion); err == nil {
			rulesChanged = true
			sversion = rulesInfo.LatestDataVersion
		} else {
			return err
		}
	}

	sconfigs := ec.currentConfigVal.Load()
	reloadReq.StaticVersion = strconv.FormatInt(sversion, 10)
	if rulesInfo.LatestSettingVersion > ec.currentConfigVal.Load().version && rulesInfo.SettingChanged {
		configsArr := toConfigsArr(rulesInfo)
		sconfigs = &ruleConfig{
			rulesConfig: configsArr,
			version:     rulesInfo.LatestSettingVersion,
		}
		configsChanged = true
	}
	reloadReq.SRuleConfigs = sconfigs.rulesConfig
	reloadReq.SConfigVersion = strconv.FormatInt(sconfigs.version, 10)
	logging.Get().Info().Int64("currRulesVersion", ec.getCurrentRulesVersion()).Int64("newRulesVersion", rulesInfo.LatestDataVersion).
		Int64("currConfigVersion", ec.currentConfigVal.Load().version).Int64("newConfigVersion", rulesInfo.LatestSettingVersion).Msg("Recieve new rules data")

	if rulesChanged || configsChanged {
		err := ec.doReloadingMozart(context.Background(), reloadReq, []byte(rulesInfo.Data), rulesChanged, configsChanged)
		if err != nil {
			logging.Get().Err(err).Str("sversion", reloadReq.StaticVersion).Msg("reload error")
			isInvalid, _ := manager.IsVersionInvalidError(err)
			if manager.IsEngineStartError(err) || isInvalid {
				// all though the version is invalid, we set the version to prevent continuously load the whole rules data before we update a valid version
				ec.setCurrentRulesVersion(sversion)
				ec.setRulesConfig(sconfigs.rulesConfig, sconfigs.version)
				logging.Get().Err(err).Str("sversion", reloadReq.StaticVersion).Msg("set the rules version when the static rules version is invalid")
			}
			return err
		} else {
			ec.setCurrentRulesVersion(sversion)
			ec.setRulesConfig(sconfigs.rulesConfig, sconfigs.version)
			logging.Get().Info().Str("sversion", reloadReq.StaticVersion).Int64("sconfigversion", sconfigs.version).Msg("reload ok")
		}
	} else {
		logging.Get().Info().Int64("dataVersion", rulesInfo.LatestDataVersion).Int64("configVersion", rulesInfo.LatestSettingVersion).
			Int64("currRVersion", ec.getCurrentRulesVersion()).Int64("currCVersion", ec.currentConfigVal.Load().version).Msg("no changes.")
	}
	return nil
}

func (ec *EngineStreamHandler) handleMsg(ctx context.Context, msg *outputs.Response) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic: %v", r)
		}
	}()

	ckey, ok := ec.cm.ClusterKey()
	if !ok {
		ckey = "-"
	}
	_, exist := filteredOutRulesSet[msg.Rule]
	if exist {
		return nil
	}

	return ec.handle(ctx, eventItem{
		data:       msg,
		clusterKey: ckey,
	})
}

func (ec *EngineStreamHandler) StartToHandle(ctx context.Context) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic: %v", r)
		}
	}()
	err := ec.engineManager.Start(ctx)
	if err != nil {
		return err
	}

	ec.asyncLoad()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic: %v", r)
			}
		}()
		for msg := range ec.engineManager.Outputs() {
			if err := ec.handleMsg(ctx, msg); err != nil {
				logging.Get().Err(err).Interface("msg", msg).Msg("handler error")
			}
		}
	}()

	return nil
}

func (ec *EngineStreamHandler) handle(ctx context.Context, e eventItem) error {
	if isEventItemWhitelisted(e.data, ec.containerInfo) {
		logging.Get().Info().Msgf("Filter out container creation post events. data: %v.", e.data)
		return nil
	}

	bd, _ := json.Marshal(e.data)
	md := make(map[string]interface{}, 9)
	_ = json.Unmarshal(bd, &md)
	md["cluster_key"] = e.clusterKey
	md["node_name"] = myNodeName
	md = mozart.ConvertKeyDotToUnderScore(md)
	outputFields, ok := md["output_fields"].(map[string]interface{})
	if !ok {
		outputFields = map[string]interface{}{}
	}
	md["output_map"] = outputFields
	md["version1"] = currentEngineLargeVersion
	err := ec.mozart.Run(mozart.Event{
		Name:    e.data.Rule,
		Payload: md,
		Time:    e.data.Time.AsTime(),
	})

	if err != nil {
		logging.Get().Error().Err(err).Interface("event", md).Msg("mozart run fails")
		return err
	}
	return nil
}

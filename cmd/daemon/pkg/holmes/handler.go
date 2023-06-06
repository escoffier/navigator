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
	"gitlab.com/piccolo_su/vegeta/pkg/holmes"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mozart"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/cryption"
	"gitlab.com/security-rd/go-pkg/logging"
	gpModel "gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/pb"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
	"gopkg.in/yaml.v2"
	"scm.tensorsecurity.cn/tensorsecurity-rd/falcosider/manager"
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

type ruleData struct {
	decodedUserData  []byte
	decodedFalcoData []byte
	falcoMozartMap   map[string][]string
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

	ruleData ruleData
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

func falcoForMozart(falcoMozartMap map[string][]string, mozartRule string) (string, bool) {
	for k, v := range falcoMozartMap {
		if util.ContainsString(v, mozartRule) {
			return k, true
		}
	}
	return "", false
}

func (ec *EngineStreamHandler) doReloadingMozart(ctx context.Context, reloadReq *pb.ReloadRequest, decodedFalcoData, decodedUserData []byte, falcoMozartMap map[string][]string, rulesChanged, configChanged bool) error {
	ec.ruleData.decodedUserData = decodedUserData
	ec.ruleData.decodedFalcoData = decodedFalcoData
	ec.ruleData.falcoMozartMap = falcoMozartMap

	var err error

	userClosedRules := make([]string, len(reloadReq.SRuleConfigs))
	for i := range reloadReq.SRuleConfigs {
		if reloadReq.SRuleConfigs[i].Disabled {
			userClosedRules[i] = reloadReq.SRuleConfigs[i].RuleKey
		}
	}
	userClosedRulesMap := mozart.BuildUserClosedRulesMap(userClosedRules)

	falcoRules := make([]model.FalcoYaml, 0)
	err = yaml.Unmarshal(decodedFalcoData, &falcoRules)
	if err != nil {
		return err
	}

	userYamlRules := make([]gpModel.UserRuleYaml, 0)
	err = yaml.Unmarshal(decodedUserData, &userYamlRules)
	if err != nil {
		return err
	}

	newV := reloadReq.StaticVersion + ";" + reloadReq.SConfigVersion
	disabledFalco := make([]*pb.RuleConfig, 0)
	userRules := make([]mozart.Rule, 0, 150)
	mozartUsersMap := make(map[string][]mozart.Rule)

	if rulesChanged {
		// 规则数据变化，重新load规则
		for i := range userYamlRules {
			for j := range userYamlRules[i].MozartParts {
				userRules = append(userRules, mozart.Rule{
					Key:      userYamlRules[i].Key,
					Name:     userYamlRules[i].Name,
					Enabled:  userYamlRules[i].Enabled,
					Trigger:  userYamlRules[i].MozartParts[j].Trigger,
					Relateds: userYamlRules[i].MozartParts[j].Relateds,
					Steps:    userYamlRules[i].MozartParts[j].Steps,
					Type:     userYamlRules[i].MozartParts[j].Type,
					Default:  userYamlRules[i].MozartParts[j].Default,
				})
			}
		}
	} else if configChanged {
		// 规则数据没有变，只是配置变化：读现有规则，如果没有现有规则，则报错
		var ok bool
		userRules, ok = ec.mozart.GetActiveRules()
		if !ok {
			logging.Get().Warn().Err(err).Str("active version", ec.mozart.GetActiveRulesVersion()).Msg("mozart GetActiveRules fails")
			return errors.New("get active rules failed")
		}
	}
	if configChanged { // 配置发生变化，修改userRule的开关
		for i := range userRules {
			if _, ok := userClosedRulesMap[userRules[i].Name]; ok {
				userRules[i].Enabled = false
			} else {
				userRules[i].Enabled = true
			}
		}
	}

	if err = ec.mozart.FillUpRegoPreQueries(ctx, userRules); err != nil {
		logging.Get().Error().Err(err).Msg("FillUpRegoPreQueries fails")
	}

	for i := range userRules {
		if rs, ok := mozartUsersMap[userRules[i].Key]; ok {
			mozartUsersMap[userRules[i].Key] = append(rs, userRules[i])
		} else {
			mozartUsersMap[userRules[i].Key] = []mozart.Rule{userRules[i]}
		}
	}

	mozartBranches := mozart.BuildMozartBranches(userRules)
	reverseUserRelateds := mozart.BuildReverseUserRelateds(userRules)

	mozartMap := make(map[string]gpModel.MozartYaml)
	for i := range userYamlRules {
		for j := range userYamlRules[i].MozartYamls {
			mozartMap[userYamlRules[i].MozartYamls[j].Key] = userYamlRules[i].MozartYamls[j]
		}
	}

	userMap := make(map[string]mozart.Rule)
	for i := range userRules {
		userMap[userRules[i].Name] = userRules[i]
	}

	// 判断falco是否应该关闭
	for i := range falcoRules {
		// 跳过marco
		if falcoRules[i].Macro != "" || falcoRules[i].List != "" {
			continue
		}
		disabled, err := mozart.CheckFalcoDisabled(falcoRules[i], mozartMap, falcoMozartMap, mozartBranches, mozartUsersMap, reverseUserRelateds, userClosedRulesMap)
		if err != nil {
			logging.Get().Error().Err(err).Msg("CheckFalcoDisabled fails")
			continue
		}
		if disabled {
			disabledFalco = append(disabledFalco, &pb.RuleConfig{RuleKey: falcoRules[i].Rule, Disabled: true})
		}
	}

	err = ec.mozart.UpdateRules(mozart.RuleUpdateOperationAdd, newV, userRules, falcoMozartMap)
	if err != nil {
		logging.Get().Error().Err(err).Msg("update mozart rules fails")
		return err
	}

	reloadReq.SRuleConfigs = disabledFalco

	// 同步更新engine，并等待结果
	err = ec.engineManager.ReloadEngine(context.Background(), reloadReq)
	if err != nil {
		logging.Get().Err(err).Str("sversion", reloadReq.StaticVersion).Msg("reload error")

		merr := ec.mozart.UpdateRules(mozart.RuleUpdateOperationDel, newV, nil, nil)
		if merr != nil {
			logging.Get().Error().Err(merr).Msg("update mozart rules fails")
			return merr
		}
		return err
	} else {
		logging.Get().Info().Str("sversion", reloadReq.StaticVersion).Msg("reload ok")
		err = ec.mozart.UpdateRules(mozart.RuleUpdateOperationDel, ec.mozart.GetActiveRulesVersion(), nil, nil)
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

	rulesInfo, err := dal.LoadAttackRules(ctx, ec.config.CtrlServerUrl, model.CurrentEngineLargeVersion, ec.getCurrentRulesVersion(), ec.currentConfigVal.Load().version)
	if err != nil {
		logging.Get().Error().Err(err).Msg("LoadAttackRules fails")
		return err
	}
	rulesChanged, configsChanged := false, false
	sversion := ec.getCurrentRulesVersion()
	reloadReq := new(pb.ReloadRequest)
	var header cryption.FileHeader
	var decodedUserData []byte             // 未aes加密、未base64编码 的 mozart规则
	var decodedFalcoData []byte            // 未aes加密、未base64编码 的 falco规则
	var falcoMozartMap map[string][]string // falco rule 和 mozart rules 的映射。key为falco rule.Name, value为对应的mozart []rule.Key
	sconfigs := ec.currentConfigVal.Load() // 当前的规则开关和版本号，刚启动时为空；规则settings变化时，会下发最新的规则开关

	if rulesInfo.LatestDataVersion > ec.getCurrentRulesVersion() && rulesInfo.DataChanged {
		rulesChanged = true
		header, decodedUserData, err = manager.DoRulesDecode([]byte(rulesInfo.Data))
		if err != nil {
			logging.Get().Error().Err(err).Msg("rules data mozart decode fails")
			return err
		}
		if debugMode {
			// DEBUG start
			logging.Get().Info().Uints16("version", header.Version[:]).Msg("DEBUG updated mozart rules")
			ec.saveToDir(decodedUserData, 888888)
			// DEBUG end
		}
		decodedFalcoData, falcoMozartMap, err = mozart.UserRule2Falco(decodedUserData)
		if err != nil {
			logging.Get().Error().Err(err).Msg("UserRule2Falco converts fails")
			return err
		}
		if debugMode {
			// DEBUG start
			logging.Get().Info().Uints16("version", header.Version[:]).Msg("DEBUG updated mozart rules")
			ec.saveToDir(decodedUserData, 888888)
			// DEBUG end
		}
		encodedFalcoData, err := holmes.ToThrBytes(decodedFalcoData, header.Version)
		if err != nil {
			logging.Get().Error().Err(err).Msg("ToThrBytes encode fails")
			return err
		}
		base64FalcoData := base64.StdEncoding.EncodeToString(encodedFalcoData)
		if err := ec.saveToDir([]byte(base64FalcoData), rulesInfo.LatestDataVersion); err == nil {
			sversion = rulesInfo.LatestDataVersion
		} else {
			return err
		}
		if debugMode {
			// DEBUG start
			logging.Get().Info().Uints16("version", header.Version[:]).Msg("DEBUG updated falco rules")
			ec.saveToDir(decodedFalcoData, 9999999)
			// DEBUG end
		}

	} else {
		decodedUserData = ec.ruleData.decodedUserData
		decodedFalcoData = ec.ruleData.decodedFalcoData
		falcoMozartMap = ec.ruleData.falcoMozartMap
	}

	if rulesInfo.LatestSettingVersion > ec.currentConfigVal.Load().version && rulesInfo.SettingChanged {
		configsChanged = true
		configsArr := toConfigsArr(rulesInfo)
		sconfigs = &ruleConfig{
			rulesConfig: configsArr,
			version:     rulesInfo.LatestSettingVersion,
		}
	}

	reloadReq.StaticVersion = strconv.FormatInt(sversion, 10)
	reloadReq.SRuleConfigs = sconfigs.rulesConfig
	reloadReq.SConfigVersion = strconv.FormatInt(sconfigs.version, 10)
	logging.Get().Info().Int64("currRulesVersion", ec.getCurrentRulesVersion()).Int64("newRulesVersion", rulesInfo.LatestDataVersion).
		Int64("currConfigVersion", ec.currentConfigVal.Load().version).Int64("newConfigVersion", rulesInfo.LatestSettingVersion).Msg("Recieve new rules data")

	if rulesChanged || configsChanged {
		err := ec.doReloadingMozart(ctx, reloadReq, decodedFalcoData, decodedUserData, falcoMozartMap, rulesChanged, configsChanged)
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
	md["version1"] = model.CurrentEngineLargeVersion
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

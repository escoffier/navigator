package holmes

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/pb"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
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
)

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

	currentRulesVersion int64
	currentConfigVal    *atomic.Pointer[ruleConfig]
}

type ruleConfig struct {
	rulesConfig []*pb.RuleConfig
	version     int64
}

func NewEventsStreamHandler(config EngineStreamConfig, cm *k8s.ClusterInfoManager, containerInfo nodeinfo.ContainerInfoManager, podResInfo *nodeinfo.PodResInfo, palaceHandler *palace.Palace) *EngineStreamHandler {
	h := &EngineStreamHandler{
		config: config,

		engineManager: manager.NewEngineManager(config.RulesDirPath, config.UnixSocketPath, config.MyNamespace),
		cm:            cm,
		containerInfo: containerInfo,
		podResInfo:    podResInfo,
		palaceHandler: palaceHandler,

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
func (ec *EngineStreamHandler) engineReloads(ctx context.Context) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("panic: %v", r)
		}
	}()

	rulesInfo, err := dal.LoadAttackRules(context.Background(), ec.config.CtrlServerUrl, ec.getCurrentRulesVersion(), ec.currentConfigVal.Load().version)
	if err != nil {
		return err
	}
	rulesChanged, configsChanged := false, false
	sversion := ec.getCurrentRulesVersion()
	reloadReq := new(pb.ReloadRequest)
	if rulesInfo.LatestDataVersion > ec.getCurrentRulesVersion() {
		if err := ec.saveToDir([]byte(rulesInfo.Data), rulesInfo.LatestDataVersion); err == nil {
			rulesChanged = true
			sversion = rulesInfo.LatestDataVersion
		} else {
			return err
		}
	}
	sconfigs := ec.currentConfigVal.Load()
	reloadReq.StaticVersion = strconv.FormatInt(sversion, 10)
	reloadReq.SConfigVersion = strconv.FormatInt(ec.currentConfigVal.Load().version, 10)
	if rulesInfo.LatestSettingVersion > ec.currentConfigVal.Load().version {
		configsArr := toConfigsArr(rulesInfo)
		sconfigs = &ruleConfig{
			rulesConfig: configsArr,
			version:     rulesInfo.LatestSettingVersion,
		}
		configsChanged = true
	}
	reloadReq.SRuleConfigs = sconfigs.rulesConfig

	if rulesChanged || configsChanged {
		err := ec.engineManager.ReloadEngine(context.Background(), reloadReq)
		if err != nil {
			logging.Get().Err(err).Str("sversion", reloadReq.StaticVersion).Msg("reload error")
			return err
		} else {
			ec.setCurrentRulesVersion(sversion)
			ec.setRulesConfig(sconfigs.rulesConfig, sconfigs.version)
			logging.Get().Info().Str("sversion", reloadReq.StaticVersion).Msg("reload ok")
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

	logging.Get().Debug().Interface("data", e.data).Msg("ATT&CK handle")
	ruleCategory := "ATT&CK"
	for _, tag := range e.data.Tags {
		if tag == "Watson" || tag == "ATT&CK" {
			ruleCategory = tag
			break
		}
	}

	ruleKey := palace.RuleKey{
		Category: ruleCategory,
		Name:     e.data.Rule,
	}

	clusterName, ok := ec.cm.ClusterName()
	if !ok {
		clusterName = e.clusterKey
	}

	signalContext, podUID, podName, namespace := generateSignalContext(e.data)
	containerID, _ := signalContext[model.FieldContainerID].(string)
	containerName, _ := signalContext[model.FieldContainerName].(string)
	if containerName == "" {
		var err error
		containerName, err = model.GetInfoFromOutput("container_name=", e.data.Output)
		if err != nil || containerName == "<NA>" {
			containerName = containerID
		}
	}

	// 所有告警均存在 cluster + hostname
	scopes := []palace.Scope{
		{
			Kind: palace.ScopeKindCluster,
			ID:   e.clusterKey,
			Name: clusterName, // cluster name
		},
		{
			Kind: palace.ScopeKindHostname,
			Name: myNodeName,
		},
	}

	if namespace != "" {
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindNamespace,
			Name: namespace,
		})
	}

	ownerRes, _, exist := ec.getOwnerInfo(podName, namespace)
	if exist {
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindResource,
			Name: fmt.Sprintf("%s(%s)", ownerRes.Name, ownerRes.Kind),
		})
	}

	if podName != "" {
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindPod,
			ID:   podUID,
			Name: podName,
		})
	}

	// 明确不是主机告警，追加 container
	if containerID != "host" {
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindContainer,
			ID:   containerID,   // container id
			Name: containerName, // container name
		})

		if namespace != "" || podName != "" {
			// in k8s
			scopes = append(scopes, palace.Scope{
				Kind: palace.ScopeKindScene,
				ID:   palace.ScopeIDSceneK8s,
				Name: palace.ScopeNameSceneK8s,
			})
		} else {
			// in not k8s
			scopes = append(scopes, palace.Scope{
				Kind: palace.ScopeKindScene,
				ID:   palace.ScopeIDSceneNk8s,
				Name: palace.ScopeNameSceneNk8s,
			})
		}
	} else {
		// in node
		scopes = append(scopes, palace.Scope{
			Kind: palace.ScopeKindScene,
			ID:   palace.ScopeIDSceneHost,
			Name: palace.ScopeNameSceneHost,
		})
	}

	err := ec.palaceHandler.SendSignal(ruleKey, scopes, signalContext)
	if err != nil {
		logging.Get().Err(err).Str("args", fmt.Sprintf("%+v", e.data)).Msg("ATT&CK send signal to palace fails!")
	}

	return nil
}

func generateSignalContext(data *outputs.Response) (signalContext map[string]interface{}, podUID, podName, namespace string) {
	signalContext = map[string]interface{}{}

	ppid, err := model.GetInfoFromOutput("proc_ppid=", data.Output)
	if err != nil {
		ppid = ""
	}
	procPname, err := model.GetInfoFromOutput("proc_pname=", data.Output)
	if err == nil {
		if len(ppid) > 0 {
			signalContext[model.FieldParentProcessName] = procPname + fmt.Sprintf("(%s)", ppid)
			delete(data.OutputFields, model.FieldParentProcessName)
		}
	}

	command, err := model.GetInfoFromOutput("proc_cmdline=", data.Output)
	if err != nil {
		command = ""
	}
	pid, err := model.GetInfoFromOutput("proc_pid=", data.Output)
	if err != nil {
		pid = ""
	}
	if command != "" && pid != "" {
		signalContext[model.FieldProcessName] = strings.Split(command, " ")[0] + fmt.Sprintf("(%s)", pid)
		delete(data.OutputFields, model.FieldProcessName)
	}

	if podName = data.OutputFields[model.FieldK8sPodName]; podName == "<NA>" {
		podName = ""
	}
	if namespace = data.OutputFields[model.FieldK8sNsName]; namespace == "<NA>" {
		namespace = ""
	}
	podUID = data.OutputFields[model.FieldPodUID]

	for key, value := range data.OutputFields {
		if value == "<NA>" {
			value = ""
		}

		if util.ContainsString(filteredOutFields, key) {
			continue
		}

		signalContext[key] = value

		if value == "" {
			switch key {
			case model.FieldProcessPid:
				if pid != "" {
					signalContext[model.FieldProcessPid] = pid
				}
			case model.FieldParentProcessPid:
				if ppid != "" {
					signalContext[model.FieldParentProcessPid] = ppid
				}
			case model.FieldCmdline:
				if len(command) > 0 {
					signalContext[model.FieldCmdline] = command
				}
			case "user":
				user, _ := model.GetInfoFromOutput("user=", data.Output)
				if len(user) > 0 {
					signalContext["user"] = user
				}
			case model.FieldSyscallType:
				if syscall, _ := model.GetInfoFromOutput("syscall_name=", data.Output); len(syscall) > 0 {
					signalContext[model.FieldSyscallType] = syscall
				}
			}
		}
	}

	// if data.Hostname != "" {
	// 	signalContext["nodeName"] = data.Hostname
	// }

	return signalContext, podUID, podName, namespace
}

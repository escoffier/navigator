package attck

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/avast/retry-go"
	"github.com/go-redis/redis/v8"
	"github.com/go-redsync/redsync/v4"
	"github.com/go-redsync/redsync/v4/redis/goredis/v8"
	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/holmes"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mozartcommon"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/cryption"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gopkg.in/yaml.v2"
	"gorm.io/gorm"
)

type updateConfigTrigger uint8

const (
	currentRulesVersion = 2
	minPocVersion       = 2
	localRulesDirPath   = "/rules"

	updateTriggerInit                 updateConfigTrigger = 0
	updateTriggerCustomConfigsPending updateConfigTrigger = 1
	updateTriggerRulesUpdated         updateConfigTrigger = 2
	updateTriggerSwitchUpdated        updateConfigTrigger = 3
)

var (
	ErrVersionNotUpper     = errors.New("the given version is not upper than the latest")
	ErrNotFalcoRuleElement = errors.New("this is not a rule element")
)

type ATTCKHandler struct {
	db             *databases.RDBInstance
	sherlockClient *echelper.SherlockClient
	rulesManager   *RulesManager
	isPOCEnabled   bool

	cacheLock sync.RWMutex
	rules     map[uint16]*attckRules
	rs        *redsync.Redsync
}

type attckRules struct {
	currentVersion *model.ATTCKConfVersion
	items          map[string]*ruleItem
	sortedItems    []*ruleItem
	cacheLock      sync.RWMutex
	baseOffset     uint64
	onlineOffset   uint64
}

type ruleItem struct {
	name        string
	ruleType    string
	description string
	severity    uint8
	hthreats    uint8
	adapter     map[string]map[string]string
	disabled    bool
	category    string
}

const (
	nameKey        = "name"
	descriptionKey = "description"
	typeKey        = "type"
)

func compare(a, b *ruleItem) bool {
	if a.ruleType < b.ruleType {
		return true
	}

	if a.ruleType > b.ruleType {
		return false
	}

	return a.name < b.name
}

var (
	ErrInvalidRuleData      = errors.New("invalid rule data")
	ErrInvalidRulesVersion1 = errors.New("invalid rules version1")
)

type RulesVersion struct {
	Seg1 uint16
	Seg2 uint16
}

func (rv *RulesVersion) String() string {
	return fmt.Sprintf("v%d.%d", rv.Seg1, rv.Seg2)
}

func parseFalcoRule(item model.RuleFromYaml) (isStrict bool, target ruleItem, err error) {
	if len(item.Rule) == 0 || len(item.Priority) == 0 {
		return isStrict, target, ErrNotFalcoRuleElement
	}
	if util.ContainsString(item.Tags, "strict") {
		isStrict = true
	}

	ruleType, err := model.GetInfoFromOutput("rule_type=", item.Output)
	if err != nil {
		ruleType = "Other"
	}
	ruleTypeZh := model.TranslateRuleType(ruleType)
	ruleTypeEn := model.TranslateENRuleType(ruleType)
	descZh := ""
	zhMsg, err := model.GetInfoFromOutput("zh_msg=", item.Output)
	if err != nil {
		return isStrict, target, err
	}

	if len(strings.Split(zhMsg, ";")) < 2 {
		descZh = strings.Split(zhMsg, ";")[0]
	} else {
		descZh = strings.Split(zhMsg, ";")[1]
	}

	tsAdapter := make(map[string]map[string]string, 2)
	tsAdapter[string(lang.LanguageZH)] = make(map[string]string, 2)
	tsAdapter[string(lang.LanguageZH)][typeKey] = ruleTypeZh
	tsAdapter[string(lang.LanguageZH)][descriptionKey] = descZh
	tsAdapter[string(lang.LanguageEN)] = make(map[string]string, 2)
	tsAdapter[string(lang.LanguageEN)][typeKey] = ruleTypeEn
	tsAdapter[string(lang.LanguageEN)][descriptionKey] = item.Desc

	// for the prevention of ambiguity, we have "_" instead of " "(space). This is for the recovery
	ruleType = strings.ReplaceAll(ruleType, "_", " ")
	return isStrict, ruleItem{
		name:        item.Rule,
		description: item.Desc,
		severity:    model.Str2SeverityNum(item.Priority),
		hthreats:    item.Hthreats,
		ruleType:    ruleType,
		adapter:     tsAdapter,
		category:    item.Category,
	}, nil
}

type mozartRuleItem struct {
	isStrict bool
	rule     ruleItem
}

func parseMozartRule(configMozart model.ConfigMozart, mozartMarco []model.ConfigMozartMarco) ([]mozartRuleItem, error) {
	mozartRules := make([]mozartRuleItem, 0)
	isStrict := !configMozart.Enabled
	values := map[string]interface{}{"0": map[string]interface{}{}}
	ruleEnName := ""
	for j := range configMozart.Steps {
		// 理论上，一个mozart规则，即使有多个分支，也应该只有一个 execGenerateSignal，只不过会通过参数赋值产生多个最终规则
		if configMozart.Steps[j].Name == "execGenerateSignal" {
			params, _ := configMozart.Steps[j].Params.(map[interface{}]interface{})
			for k, v := range params {
				if k.(string) == "rule" {
					ruleEnName = v.(string)
				}
			}
		}
		innerValues, err := mozartcommon.ExtractValues(context.Background(), configMozart.Steps[j], mozartMarco, "0")
		if err != nil {
			return nil, err
		}
		for ik, iv := range innerValues {
			values["0"].(map[string]interface{})[ik] = iv
		}
	}
	flatValues := mozartcommon.FlatValues(values)
	if ruleEnName == "" {
		err := errors.New("no invalid rule en name")
		logging.Get().Error().Err(err).Msg("no invalid rule en name")
		return nil, err
	}
	if len(flatValues) == 0 {
		flatValues = []map[string]interface{}{{}} // 无变量赋值，使用空配置
	} else if mozartcommon.CheckDefaultFormatValue(ruleEnName) { // 存在默认值
		flatValues = append(flatValues, map[string]interface{}{})
	}
	for i := range flatValues {
		iDescZh, err := mozartcommon.TemplateFormat(configMozart.Info.Desc.Zh, flatValues[i])
		if err != nil {
			return nil, err
		}
		iDescEn, err := mozartcommon.TemplateFormat(configMozart.Info.Desc.En, flatValues[i])
		if err != nil {
			return nil, err
		}
		iRuleEnName, err := mozartcommon.TemplateFormat(ruleEnName, flatValues[i])
		if err != nil {
			return nil, err
		}
		hthreats := 0
		if configMozart.Info.Urgency {
			hthreats = 1
		}
		tsAdapter := make(map[string]map[string]string, 2)
		tsAdapter[string(lang.LanguageZH)] = make(map[string]string, 2)
		tsAdapter[string(lang.LanguageZH)][typeKey] = model.TranslateRuleType(configMozart.Info.RuleType)
		tsAdapter[string(lang.LanguageZH)][descriptionKey] = iDescZh.(string)
		tsAdapter[string(lang.LanguageEN)] = make(map[string]string, 2)
		tsAdapter[string(lang.LanguageEN)][typeKey] = model.TranslateENRuleType(configMozart.Info.RuleType)
		tsAdapter[string(lang.LanguageEN)][descriptionKey] = iDescEn.(string)

		mozartRules = append(mozartRules, mozartRuleItem{
			isStrict: isStrict,
			rule: ruleItem{
				name:        iRuleEnName.(string),
				description: configMozart.Info.Desc.En,
				severity:    model.Str2SeverityNum(configMozart.Info.Priority),
				hthreats:    uint8(hthreats),
				ruleType:    strings.ReplaceAll(configMozart.Info.RuleType, "_", " "),
				adapter:     tsAdapter,
				category:    "ATT&CK",
			},
		})
	}

	return mozartRules, nil
}

func encode(ctx context.Context, before RawData) ([]byte, error) {
	encodedBytes, err := holmes.ToThrBytes(before.Data, before.Version)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(encodedBytes)))
	base64.StdEncoding.Encode(dst, encodedBytes)
	return dst, nil
}
func decode(ctx context.Context, before []byte) (RawData, error) {
	header, decoded, _, err := cryption.ReadRulesData(before)
	if err != nil {
		return RawData{}, err
	}
	return RawData{
		Data:    decoded,
		Version: header.Version,
	}, nil
}

func NewATTCKHandler(db *databases.RDBInstance, redisCli *redis.Client, sherlockClient *echelper.SherlockClient) (*ATTCKHandler, error) {
	builder := NewManagerBuilder(db)
	builder.SetEncoder(encode)
	if ipErr := builder.InitPlugins(); ipErr != nil {
		logging.Get().Err(ipErr).Msg("init plugins error")
		return nil, ipErr
	}
	handler := &ATTCKHandler{
		db:             db,
		sherlockClient: sherlockClient,
		rulesManager:   builder.Build(),
		rules:          make(map[uint16]*attckRules, 0),
		rs:             redsync.New(goredis.NewPool(redisCli)),
		isPOCEnabled:   len(os.Getenv(EnvKeyDPTags)) > 0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for i := 1; i <= currentRulesVersion; i++ {
		err := handler.updateConfigs(ctx, uint16(i), updateTriggerInit)
		if err != nil {
			return nil, err
		}
	}

	go handler.asyncLoop()
	return handler, nil
}

func (h *ATTCKHandler) loadFromLocal(ctx context.Context, v uint16) ([]byte, error) {
	fileInfos, err := os.ReadDir(localRulesDirPath)
	if err != nil {
		logging.Get().Err(err).Str("path", localRulesDirPath).Msg("load from local dir error.")
		return nil, err
	}
	for _, fileInfo := range fileInfos {
		if !fileInfo.IsDir() && strings.HasPrefix(fileInfo.Name(), fmt.Sprintf("holmes-rules-v%d.", v)) {
			return os.ReadFile(localRulesDirPath + "/" + fileInfo.Name())
		}
	}

	return nil, errors.New("no local file of such version")
}

func (h *ATTCKHandler) GetRuleInfo(ctx context.Context, ruleKey string) (*HolmesRule, bool) {
	return h.rulesManager.getRule(ctx, ruleKey)
}
func (h *ATTCKHandler) parseItems(header cryption.FileHeader, rulesContext []byte) (version RulesVersion, rules map[string]*ruleItem, strictRules map[string]struct{}, err error) {
	version = RulesVersion{
		header.Version[0],
		header.Version[1],
	}

	var fDataRules []model.RuleFromYaml
	err = yaml.Unmarshal(rulesContext, &fDataRules)
	if err != nil {
		logging.Get().Err(err).Msg("unmarshal rule fail")
		return version, nil, nil, ErrInvalidRuleData
	}

	// rules为会触发告警，会由用户控制开关的规parseItems则
	rules = make(map[string]*ruleItem, len(fDataRules))
	strictRules = make(map[string]struct{}, len(fDataRules)/3)

	// 针对不同的规则版本，进行分别的解析
	switch version.Seg1 {
	// falco
	case 1:
		for _, item := range fDataRules {
			isStrict, rule, err := parseFalcoRule(item)
			if err == ErrNotFalcoRuleElement {
				continue
			} else if err != nil {
				logging.Get().Err(err).Interface("item", item).Msg("Parse falco rule error")
				continue
			}

			if isStrict {
				strictRules[rule.name] = struct{}{}
			}
			rules[rule.name] = &rule
		}

	// falco + mozart
	case 2:

		var mozartMarco []model.ConfigMozartMarco
		for i := range fDataRules {
			if len(fDataRules[i].MozartMarco) == 0 {
				continue
			}
			mozartMarco = fDataRules[i].MozartMarco
			break
		}
		for _, item := range fDataRules {
			// 处理mozart规则
			if len(item.Mozart) != 0 {
				for i := range item.Mozart {
					mozartRuleItems, err := parseMozartRule(item.Mozart[i], mozartMarco)
					if err != nil {
						logging.Get().Err(err).Interface("item", item.Mozart).Msg("Parse mozart error")
						continue
					}
					for j := range mozartRuleItems {
						rules[mozartRuleItems[j].rule.name] = &mozartRuleItems[j].rule
						if mozartRuleItems[j].isStrict {
							strictRules[mozartRuleItems[j].rule.name] = struct{}{}
						}
					}
				}
				// mozart规则列表下，没有正常的falco规则，跳过
				continue
			}

			// 只是关联规则，不应展示，跳过
			if !util.ContainsString(item.Tags, "triggered") && util.ContainsString(item.Tags, "related") {
				continue
			}
			// 触发规则严重级别较低，不应展示，跳过
			if util.ContainsString(item.Tags, "triggered") && !rtdetect.ComparePriority(item.Priority, "ERROR") {
				continue
			}

			// falco
			isStrict, rule, err := parseFalcoRule(item)
			if err == ErrNotFalcoRuleElement {
				continue
			} else if err != nil {
				logging.Get().Err(err).Interface("item", item).Msg("Parse falco rule error")
				continue
			}
			if isStrict {
				strictRules[rule.name] = struct{}{}
			}
			rules[rule.name] = &rule

		}
	}

	return version, rules, strictRules, nil
}

func (h *ATTCKHandler) loadFromStore(ctx context.Context, v uint16) (*model.ATTCKRuleData, error) {
	tctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var conf *model.ATTCKRuleData
	var notFoundErr error
	err := util.RetryWithBackoff(tctx, func() error {
		var err error
		conf, err = dal.LoadATTCKConfDataByVersion1(ctx, h.db.Get(), v)
		if err == dal.ErrATTCKConfDataNotFound {
			notFoundErr = err
			return nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if notFoundErr != nil || conf == nil {
		return nil, notFoundErr
	}
	return conf, nil
}

func (h *ATTCKHandler) asyncUploadRulesToEventsCenter(ruleBytes []byte, version string) {
	go func() {
		for {
			toContinue := func() bool {
				defer func() {
					if r := recover(); r != nil {
						logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("Panic: %v.", r)
					}
				}()
				tctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				err := util.RetryWithBackoff(tctx, func() error {
					oneCtx, cancel := context.WithTimeout(tctx, 5*time.Second)
					defer cancel()

					return echelper.SendRulesToEventCenter(oneCtx, h.sherlockClient, ruleBytes, version)
				})
				if err != nil {
					logging.Get().Err(err).Str("conf version", version).Msg("send to events center error.")
					return true
				} else {
					logging.Get().Info().Str("conf version", version).Msg("successfully upload to events center.")
					return false
				}
			}()
			if toContinue {
				time.Sleep(1 * time.Minute)
			} else {
				break
			}
		}
	}()
}

// compareVersion returns true if the new version is upper than the latestConf
func compareVersion(latestConf *model.ATTCKRuleData, toCompareHeader cryption.FileHeader) bool {
	if latestConf == nil {
		return true
	}
	primVersion := latestConf.Version1
	secondaryVersion := latestConf.Version2
	if primVersion == toCompareHeader.Version[0] {
		return secondaryVersion < toCompareHeader.Version[1]
	} else {
		return primVersion < toCompareHeader.Version[0]
	}
}

type MultiLang map[string]string

type RuleInfo struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	CategoryKey string `json:"categoryKey"`
	Module      string `json:"module"`
	Severity    int    `json:"severity"`
	Hthreats    int    `json:"hthreats"`
}
type InitConfig struct {
	Rule          RuleInfo      `json:"rule"`
	CustomSetting CustomSetting `json:"customSetting"`
	Effect        string        `json:"effect"`
}

func (h *ATTCKHandler) GetCustomInitConfig(ctx context.Context, language string) ([]*InitConfig, error) {
	initConfigs, exist := h.rulesManager.getCustomInitConfigs(ctx)
	if !exist {
		return nil, errors.New("init configs not exist")
	}
	iconfs := make([]*InitConfig, 0, len(initConfigs))
	for _, initConfig := range initConfigs {
		for _, steps := range initConfig.RulesAppliedSteps {
			if len(steps) == 0 {
				continue
			}
			iconf := new(InitConfig)
			iconf.CustomSetting.Key = initConfig.Key
			iconf.CustomSetting.Name = initConfig.Name[language]
			iconf.CustomSetting.Type = initConfig.Type
			iconf.Rule.Key = steps[0]
			rinfo, exist := h.GetRuleInfo(ctx, steps[0])
			if !exist {
				logging.Get().Error().Str("ruleKey", steps[0]).Msg("cannot find the rule from store")
				continue
			}
			iconf.Rule.Category = rinfo.Category[language]
			iconf.Rule.CategoryKey = rinfo.Category[string(lang.LanguageEN)]
			iconf.Rule.Name = rinfo.Name[language]
			iconf.Rule.Description = rinfo.Description[language]
			iconf.Rule.Hthreats = int(rinfo.Hthreats)
			iconf.Rule.Severity = int(rinfo.Severity)
			iconf.Rule.Module = "ATT&CK"
			iconf.Effect = initConfig.Effect[language]

			iconfs = append(iconfs, iconf)
		}

	}
	return iconfs, nil
}

type CustomConfigsQueryOption struct {
	RuleKey        string
	Query          string
	RuleCategories []string
	ID             uint64
	CconfigKeys    []string
	Statuses       []model.CconfigStatus
}

type CustomConfigItem struct {
	ID            uint64        `json:"id"`
	Rule          RuleInfo      `json:"rule"`
	CustomSetting CustomSetting `json:"customSetting"`
	Effect        string        `json:"effect"`
	Updater       string        `json:"updater"`
	UpdatedAt     int64         `json:"updatedAt"`
}

func (h *ATTCKHandler) GetCustomConfigs(ctx context.Context, query CustomConfigsQueryOption, limit, offset int, lang string) ([]CustomConfigItem, int, error) {
	var queryFunc dal.QueryBuilderFunc
	if len(query.Query) > 0 {
		var candidatedRuleKeys []string
		store, exist := h.rulesManager.getStore(ctx)
		if exist && store != nil {
			rules, err := store.ISearch(ctx, query.Query)
			if err == nil {
				candidatedRuleKeys = make([]string, len(rules))
				for i, r := range rules {
					candidatedRuleKeys[i] = r.Key
				}
			} else {
				logging.Get().Err(err).Str("query", query.Query).Msg("rule names isearch error")
			}
		} else {
			logging.Get().Warn().Str("query", query.Query).Msg("no store")
		}
		queryFunc = func(db *gorm.DB) *gorm.DB {
			db = db.Order("updated_at DESC")
			if len(candidatedRuleKeys) > 0 {
				return db.Where("rule_key in ? OR LOWER(cconfig_value) LIKE LOWER(?)", candidatedRuleKeys, dal.GetLikeExpr(query.Query))
			}
			return db.Where("LOWER(cconfig_value) LIKE LOWER(?)", dal.GetLikeExpr(query.Query))
		}
	} else {
		queryFunc = func(db *gorm.DB) *gorm.DB {
			return db.Order("updated_at DESC")
		}
	}
	dalQuery := dal.NewCustomConfigsOption()
	if len(query.RuleKey) > 0 {
		dalQuery.WithEqual("rule_key", query.RuleKey)
	}
	if len(query.RuleCategories) > 0 {
		dalQuery.WithIn("rule_category", query.RuleCategories)
	}
	if query.ID > 0 {
		dalQuery.WithEqual("id", query.ID)
	}
	if len(query.CconfigKeys) > 0 {
		dalQuery.WithIn("cconfig_key", query.CconfigKeys)
	}
	if len(query.Statuses) > 0 {
		dalQuery.WithIn("status", query.Statuses)
	}

	list, err := dal.GetCustomConfigs(ctx, h.db.GetReadDB(), dalQuery, queryFunc, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	retList := make([]CustomConfigItem, len(list))
	for i, dbItem := range list {
		retList[i].ID = dbItem.ID
		retList[i].CustomSetting.Key = dbItem.CconfigKey
		var valueList []string
		if len(dbItem.CconfigValue) > 0 {
			err := json.Unmarshal([]byte(dbItem.CconfigValue), &valueList)
			if err != nil {
				logging.Get().Err(err).Any("item", dbItem).Msg("unmarshal error")
				return nil, 0, err
			}
		}
		retList[i].CustomSetting.Value = valueList
		retList[i].UpdatedAt = dbItem.UpdatedAt
		retList[i].Updater = dbItem.Updater

		retList[i].Rule.Key = dbItem.RuleKey
		store, exist := h.rulesManager.getStore(ctx)
		if exist && store != nil {
			rinfo, exist := store.GetRule(context.Background(), dbItem.RuleKey)
			if exist {
				retList[i].Rule.Description = rinfo.Description[lang]
				retList[i].Rule.Name = rinfo.Name[lang]
				retList[i].Rule.Category = rinfo.Category[lang]
				retList[i].Rule.Module = "ATT&CK"
				retList[i].Rule.Hthreats = int(rinfo.Hthreats)
				retList[i].Rule.Severity = int(rinfo.Severity)
			} else {
				logging.Get().Warn().Str("rkey", dbItem.RuleKey).Msg("cannot find the rule")
			}

			found := false
			for _, iconf := range store.GetCconfigInitConfigs() {
				if iconf.Key == dbItem.CconfigKey {
					found = true
					retList[i].CustomSetting.Name = iconf.Name[lang]
					retList[i].CustomSetting.Type = iconf.Type
					retList[i].Effect = iconf.Effect[lang]
				}
			}
			if !found {
				logging.Get().Warn().Str("ckey", dbItem.CconfigKey).Msg("cannot find the initConfig")
			}
		} else {
			logging.Get().Warn().Msg("no store")
		}
	}

	cnt, err := dal.CountCustomConfigs(ctx, h.db.GetReadDB(), dalQuery, queryFunc)
	if err != nil {
		return nil, 0, err
	}
	return retList, cnt, nil
}

type CconfigUpdateItem struct {
	ID            uint64        `json:"id,omitempty"`
	RuleKey       string        `json:"ruleKey,omitempty"`
	CustomSetting CustomSetting `json:"customSetting"`
}
type CustomSetting struct {
	Key   string   `json:"key"`
	Value []string `json:"value"`
	Type  string   `json:"type,omitempty"`
	Name  string   `json:"name,omitempty"`
}

func (h *ATTCKHandler) BatchAddCustomConfigs(ctx context.Context, data []*CconfigUpdateItem) error {
	tctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	for _, item := range data {
		merr := dal.ModifyCustomConfigValues(tctx, h.db.Get(), item.RuleKey, item.CustomSetting.Key, func(ctx context.Context, oldValue string) (newValue string, err error) {
			var list []string
			if oldValue == "" {
				list = item.CustomSetting.Value
			} else {
				jerr := json.Unmarshal([]byte(oldValue), &list)
				if jerr != nil {
					logging.Get().Err(jerr).Msg("json unmarshal err")
				} else {
					list = append(list, item.CustomSetting.Value...)
				}
			}
			list = util.ListDeduplicate(list)

			listBytes, err := json.Marshal(list)
			if err != nil {
				return "", err
			}
			return string(listBytes), nil
		})
		if merr != nil {
			logging.Get().Err(merr).Uint64("id", item.ID).Strs("updates", item.CustomSetting.Value).Msg("modify error")
			return merr
		}
	}
	return nil
}

func (h *ATTCKHandler) UpdateCustomConfigStatus(ctx context.Context, id uint64, status model.CconfigStatus) error {
	opt := dal.NewCustomConfigsOption()
	opt.WithEqual("id", id)
	return dal.SetCustomConfigStatus(ctx, h.db.Get(), opt, status)
}

func (h *ATTCKHandler) BatchEditCustomConfigs(ctx context.Context, data []*CconfigUpdateItem) error {
	tctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	for _, item := range data {
		if item.ID == 0 && item.RuleKey == "" {
			logging.Get().Error().Interface("item", item).Msg("error item with no id and rulekey")
			return errors.New("illegal argument")
		}
		item.CustomSetting.Value = util.ListDeduplicate(item.CustomSetting.Value)
		dbytes, err := json.Marshal(item.CustomSetting.Value)
		if err != nil {
			logging.Get().Err(err).Msg("marshal err")
		}
		queryOpt := dal.NewCustomConfigsOption()
		if item.ID > 0 {
			queryOpt.WithEqual("id", item.ID)
		} else if item.RuleKey != "" {
			queryOpt.WithEqual("rule_key", item.RuleKey)
		}
		err = dal.UpdateCustomConfig(tctx, h.db.Get(), queryOpt, map[string]any{"cconfig_value": string(dbytes), "status": model.StatusPending})
		if err != nil {
			logging.Get().Err(err).Uint64("id", item.ID).Strs("updates", item.CustomSetting.Value).Msg("update config err")
			return err
		}
	}
	return nil
}

func (h *ATTCKHandler) updateDefaultMasksForStricts(ctx context.Context, strictRules map[string]struct{}, v uint16) error {
	// don't check musk version must not be set. update them anyway.
	// version, err := dal.LoadATTCKRuleMaskVersion(ctx, h.db.Get())
	// if err == nil && version > 0 {
	// 	return nil
	// }
	// if err != gorm.ErrRecordNotFound {
	// 	return err
	// }
	addMusks := make([]*model.ATTCKRuleMask, 0, len(strictRules))
	for ruleName := range strictRules {
		addMusks = append(addMusks, &model.ATTCKRuleMask{
			Version1: v,
			Name:     ruleName,
		})
	}
	return dal.UpdateRuleMask(ctx, h.db.Get(), addMusks, nil, v)
}

func (h *ATTCKHandler) updateConfigs(ctx context.Context, v uint16, trigger updateConfigTrigger) error {
	var rules map[string]*ruleItem
	storeConf, dbErr := h.loadFromStore(ctx, v)
	if dbErr != nil && dbErr != dal.ErrATTCKConfDataNotFound {
		logging.Get().Err(dbErr).Msg("loadFromStore error.")
		return dbErr
	}
	loaded := false
	if trigger == updateTriggerInit {
		ruleBytes, err := h.loadFromLocal(ctx, v)
		if err != nil {
			logging.Get().Err(err).Msg("loadFromLocal error.")
			return err
		}
		header, rulesContext, _, err := cryption.ReadRulesData(ruleBytes)

		if dbErr == dal.ErrATTCKConfDataNotFound || compareVersion(storeConf, header) { // use local
			logging.Get().Info().Uints16("local version", header.Version[:]).Msg("Initialize with local rules.")
			var version RulesVersion
			var ccVersion uint64
			var strictRules map[string]struct{}

			// customized configs process
			if header.Version[0] >= 2 {
				logging.Get().Info().Msg("Try to update data by custom configs and plugins")
				customed, ccv, custerr := h.rulesManager.UpdateRules(context.Background(), rulesContext, header.Version)
				if custerr == nil {
					rulesContext = customed.Data
					ccVersion = ccv
				} else {
					logging.Get().Err(custerr).Msg("customized process rules error")
				}
			}

			version, rules, strictRules, err = h.parseItems(header, rulesContext)
			if err != nil {
				logging.Get().Err(err).Str("data", string(ruleBytes)).Msg("parse items error.")
				return err
			}

			if len(strictRules) > 0 {
				if err := h.updateDefaultMasksForStricts(ctx, strictRules, version.Seg1); err != nil {
					logging.Get().Err(err).Msg("updateDefaultMasksForStricts error")
				}
			}

			confData := model.ATTCKRuleData{
				Content:          ruleBytes,
				CconfigIDversion: ccVersion,
			}
			confData.ATTCKConfVersion = model.ATTCKConfVersion{
				Version1:  version.Seg1,
				Version2:  version.Seg2,
				Username:  "system",
				CreatedAt: time.Now(),
			}
			err = util.RetryWithBackoff(ctx, func() error {
				var err error
				storeConf, err = dal.SaveATTCKConfData(ctx, h.db.Get(), &confData, nil, version.Seg1)
				return err
			}, retry.Attempts(3))
			if err != nil {
				logging.Get().Err(err).Msg("store attck conf data error. ")
			} else {
				logging.Get().Info().Str("conf version", version.String()).Uint64("id", storeConf.ID).Msg("Successfully store attack conf data from local.")
			}

			h.asyncUploadRulesToEventsCenter(rulesContext, version.String())
			loaded = true
		}
	}

	if !loaded { // use storage
		header, rulesContext, _, err := cryption.ReadRulesData(storeConf.Content)
		logging.Get().Info().Str("storage version", storeConf.VString()).Uint16("version1", header.Version[0]).Uint16("version2", header.Version[1]).Msg("Initialize with stored rules.")
		if err != nil {
			logging.Get().Err(err).Str("data", string(storeConf.Content)).Msg("decode rule data fail")
			return err
		}
		// customized configs process
		if header.Version[0] >= 2 {
			logging.Get().Info().Msg("Try to update data by custom configs and plugins")
			ctx := context.Background()
			customed, ccVersion, custerr := h.rulesManager.UpdateRules(ctx, rulesContext, header.Version)
			if custerr == nil {
				rulesContext = customed.Data

				// if it's refreshing or it's initing but the new ccVersion is different from the previous version, we update the data offset to trigger the updates of rules
				if trigger == updateTriggerCustomConfigsPending || trigger == updateTriggerRulesUpdated || (trigger == updateTriggerInit && (h.isPOCEnabled || ccVersion != storeConf.CconfigIDversion)) {
					logging.Get().Info().Uint8("trigger", uint8(trigger)).Bool("isPOCEnabled", h.isPOCEnabled).Uint64("dataID", storeConf.ID).Uint64("cconf version", ccVersion).Msg("try to start update rules offset to push")
					ierr := dal.IncreaseATTCKDataIDAndSetConfigVersion(ctx, h.db.Get(), storeConf.ID, ccVersion)
					if ierr != nil {
						logging.Get().Err(ierr).Uint64("dataID", storeConf.ID).Uint64("cconf version", ccVersion).Msg("increase and update ccversion error")
					} else {
						storeConf.ID++
						storeConf.CconfigIDversion = ccVersion
					}
				}

			} else {
				logging.Get().Err(custerr).Msg("customized process rules error")
			}
		}
		_, rules, _, err = h.parseItems(header, rulesContext)
		if err != nil {
			logging.Get().Err(err).Msgf("parse items error. data: %s", string(storeConf.Content))
			return err
		}
	}

	onlineOffset, err := dal.LoadATTCKRuleMaskVersion(ctx, h.db.Get(), storeConf.Version1)
	if err != nil {
		logging.Get().Err(err).Msg("LoadATTCKRuleMaskVersion err.")
		return err
	}

	ruleMasks, err := dal.LoadATTCKRuleMasks(ctx, h.db.Get(), storeConf.Version1)
	if err != nil {
		logging.Get().Err(err).Msg("LoadATTCKRuleMasks err.")
		return err
	}

	h.cacheLock.Lock()
	defer h.cacheLock.Unlock()

	h.updateRulesByVersion(rules, storeConf.ID, onlineOffset, model.ATTCKConfVersion{
		Version1:  storeConf.Version1,
		Version2:  storeConf.Version2,
		Username:  storeConf.Username,
		CreatedAt: storeConf.CreatedAt,
	})

	logging.Get().Info().Msgf("baseOffset:%d, onlineOffset:%d", h.rules[storeConf.Version1].baseOffset, h.rules[storeConf.Version1].onlineOffset)
	vRules, _ := h.rules[storeConf.Version1]
	for _, mask := range ruleMasks {
		if item, ok := vRules.items[mask.Name]; ok && item != nil {
			vRules.items[mask.Name].disabled = true
		}
	}
	h.rules[storeConf.Version1] = vRules

	if v == uint16(1) {
		// fixme: 增加一个hack逻辑，当version大版本号为1时，批量更新数据库的ivan_assets_clusters.rule_version字段。   原因是 多版本集群环境下，老版集群没有同步规则库版本的逻辑
		go h.updateV1RuleVersion(ctx, fmt.Sprintf("v%d.%d", storeConf.Version1, storeConf.Version2))
	}

	return nil
}

const (
	attckLockKey = "attck-lock"
)

func (h *ATTCKHandler) obtainLock(ctx context.Context, mutex *redsync.Mutex) error {
	if err := mutex.LockContext(ctx); err != nil {
		logging.Get().Err(err).Msg("obtain attck lock fail")
		return err
	}

	return nil
}

func (h *ATTCKHandler) releaseLock(mutex *redsync.Mutex) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	if ok, err := mutex.UnlockContext(ctx); err != nil || !ok {
		logging.Get().Err(err).Msg("release attck lock fail")
	}
}

func (h *ATTCKHandler) UpdateConfig(ctx context.Context, username string, data []byte) (*model.ATTCKRuleData, error) {
	mutex := h.rs.NewMutex(attckLockKey)
	if err := h.obtainLock(ctx, mutex); err != nil {
		return nil, err
	}

	defer h.releaseLock(mutex)

	header, rulesContext, _, err := cryption.ReadRulesData(data)
	if err != nil {
		logging.Get().Err(err).Str("data", string(data)).Msg("decode rule data fail")
		return nil, err
	}

	var ccVersion uint64
	// customized configs process
	if header.Version[0] >= 2 {
		logging.Get().Info().Msg("Try to update data by custom configs and plugins")
		customed, ccv, custerr := h.rulesManager.UpdateRules(context.Background(), rulesContext, header.Version)
		if custerr == nil {
			rulesContext = customed.Data
			ccVersion = ccv
		} else {
			logging.Get().Err(custerr).Msg("customized process rules error")
		}
	}

	version, rules, strictRules, err := h.parseItems(header, rulesContext)
	if err != nil {
		return nil, err
	}
	h.flushCache(version.Seg1)

	if version.Seg1 == uint16(1) {
		// fixme: 增加一个hack逻辑，当version大版本号为1时，批量更新数据库的ivan_assets_clusters.rule_version字段。   原因是 多版本集群环境下，老版集群没有同步规则库版本的逻辑
		go h.updateV1RuleVersion(ctx, version.String())
	}

	if len(strictRules) > 0 {
		if err := h.updateDefaultMasksForStricts(ctx, strictRules, version.Seg1); err != nil {
			logging.Get().Err(err).Msg("updateDefaultMasksForStricts error")
		}
	}

	h.cacheLock.Lock()
	defer h.cacheLock.Unlock()
	var deprecatedRuleMasks []string
	vRules, ok := h.rules[version.Seg1]
	if ok {
		for _, rule := range vRules.items {
			if rule.disabled && rules[rule.name] != nil {
				// set disabled
				rules[rule.name].disabled = true
			}

			if _, ok := rules[rule.name]; !ok && rule.disabled {
				// deprecated ruleMasks
				deprecatedRuleMasks = append(deprecatedRuleMasks, rule.name)
			}
		}
	}

	nowTime := time.Now()
	confVersion := model.ATTCKConfVersion{
		Username:  username,
		Version1:  version.Seg1,
		Version2:  version.Seg2,
		CreatedAt: nowTime,
	}
	attackRuleData := &model.ATTCKRuleData{
		ATTCKConfVersion: confVersion,
		CconfigIDversion: ccVersion,
		Content:          data,
	}

	// storeConf, err := h.loadFromStore(ctx)
	if err != nil && err != dal.ErrATTCKConfDataNotFound {
		return nil, err
	}
	// temporarily remove the restriction of versions(must larger than the previous) for manual updates.
	// if storeConf != nil && !compareVersion(storeConf, header) {
	// 	logging.Get().Warn().Uints16("given version", header.Version[:]).Str("latest version", storeConf.Version).Msg("The given version is not upper than the latest version. skip updating.")
	// 	return nil, ErrVersionNotUpper
	// }

	storedRuleData, err := dal.SaveATTCKConfData(ctx, h.db.Get(), attackRuleData, deprecatedRuleMasks, version.Seg1)
	if err != nil {
		return nil, err
	}

	onlineOffset := vRules.onlineOffset
	if len(deprecatedRuleMasks) > 0 {
		onlineOffset++
	}
	h.updateRulesByVersion(rules, storedRuleData.ID, onlineOffset, confVersion)

	logging.Get().WithContext(ctx).Infof("decoding done. try to update to events center")
	h.asyncUploadRulesToEventsCenter(rulesContext, version.String())

	return attackRuleData, nil
}

func (h *ATTCKHandler) updateRulesByVersion(rules map[string]*ruleItem, baseOffset, onlineOffset uint64, version model.ATTCKConfVersion) {
	vRules, ok := h.rules[version.Version1]
	if !ok {
		vRules = new(attckRules)
	}
	vRules.baseOffset = baseOffset
	vRules.onlineOffset = onlineOffset
	vRules.currentVersion = &version
	vRules.items = rules
	vRules.sortedItems = make([]*ruleItem, 0, len(rules))
	for _, rule := range rules {
		vRules.sortedItems = append(vRules.sortedItems, rule)
	}
	sort.Slice(vRules.sortedItems, func(i, j int) bool {
		return compare(vRules.sortedItems[i], vRules.sortedItems[j])
	})

	h.rules[version.Version1] = vRules
}

type GetRuleListArg struct {
	Offset         int
	Limit          int
	SeverityFilter map[uint8]struct{}
	HthreatsFilter map[uint8]struct{}
	Query          string
	Lang           string
}

func (h *ATTCKHandler) GetRuleList(_ context.Context, arg *GetRuleListArg, v uint16) (int64, []*model.ATTCKRuleDisplay, error) {
	h.flushCache(v)
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	var items []*ruleItem
	var total int64
	var offset = arg.Offset
	vRules, ok := h.rules[v]
	if !ok {
		return total, nil, ErrInvalidRulesVersion1
	}
	for _, rule := range vRules.sortedItems {
		if (arg.Query == "" || checkRuleMatchQuery(rule, arg.Query, arg.Lang)) &&
			(len(arg.SeverityFilter) == 0 || checkSeverityFilter(rule, arg.SeverityFilter)) &&
			(len(arg.HthreatsFilter) == 0 || checkHthreatsFilter(rule, arg.HthreatsFilter)) &&
			isAttck(rule) {
			offset--
			total++
			if offset < 0 && len(items) < arg.Limit {
				items = append(items, rule)
			}
		}
	}

	var result = make([]*model.ATTCKRuleDisplay, len(items))
	for i := range items {
		result[i] = convertRuleItem(items[i], arg.Lang)
	}

	return total, result, nil
}

func convertRuleItem(item *ruleItem, lang string) *model.ATTCKRuleDisplay {
	return &model.ATTCKRuleDisplay{
		Name:        item.name,
		Type:        item.ruleType,
		Description: item.description,
		Severity:    item.severity,
		Hthreats:    item.hthreats,
		Enabled:     !item.disabled,
		Adapter:     item.adapter[lang],
	}
}

func (h *ATTCKHandler) UpdateRuleSettings(ctx context.Context, settings []*model.ATTCKRuleSwitch, v uint16) ([]*model.ATTCKRuleSwitch, error) {
	mutex := h.rs.NewMutex(attckLockKey)
	if err := h.obtainLock(ctx, mutex); err != nil {
		return nil, err
	}
	defer h.releaseLock(mutex)

	h.flushCache(v)
	h.cacheLock.Lock()
	defer h.cacheLock.Unlock()

	deletedMasks := make(map[string]struct{}, len(settings))
	addMasks := make(map[string]struct{}, len(settings))

	vRules, ok := h.rules[v]
	if !ok {
		return nil, ErrInvalidRulesVersion1
	}
	for _, setting := range settings {
		item := vRules.items[setting.Name]
		if item == nil {
			return nil, dal.ErrRuleNotExists
		}

		if item.disabled != setting.Enabled {
			continue
		}

		if setting.Enabled {
			deletedMasks[setting.Name] = struct{}{}
		} else {
			addMasks[setting.Name] = struct{}{}
		}
	}

	newMasks := util.StringSetToArray(addMasks)
	var masks = make([]*model.ATTCKRuleMask, 0, len(newMasks))
	for _, mask := range newMasks {
		masks = append(masks, &model.ATTCKRuleMask{
			Version1: v,
			Name:     mask,
		})
	}

	if len(deletedMasks) > 0 || len(addMasks) > 0 {
		if err := dal.UpdateRuleMask(ctx, h.db.Get(), masks, util.StringSetToArray(deletedMasks), v); err != nil {
			return nil, err
		}
		for _, setting := range settings {
			vRules.items[setting.Name].disabled = !setting.Enabled
		}
		vRules.onlineOffset++
	}
	h.rules[v] = vRules

	return settings, nil
}

func checkRuleMatchQuery(rule *ruleItem, query, lang string) bool {
	name := rule.name
	ruleType := rule.ruleType
	description := rule.description

	if rule.adapter[lang] != nil {
		if rule.adapter[lang][nameKey] != "" {
			name = rule.adapter[lang][nameKey]
		}

		if rule.adapter[lang][typeKey] != "" {
			ruleType = rule.adapter[lang][typeKey]
		}

		if rule.adapter[lang][descriptionKey] != "" {
			description = rule.adapter[lang][descriptionKey]
		}
	}

	return strings.Contains(name, query) || strings.Contains(ruleType, query) || strings.Contains(description, query)
}

func checkSeverityFilter(rule *ruleItem, filter map[uint8]struct{}) bool {
	_, ok := filter[rule.severity]
	return ok
}

func checkHthreatsFilter(rule *ruleItem, filter map[uint8]struct{}) bool {
	_, ok := filter[rule.hthreats]
	return ok
}

func isAttck(rule *ruleItem) bool {
	return rule.category == "" || rule.category == "ATT&CK"
}

func (h *ATTCKHandler) GetATTCKVersion(ctx context.Context) (*model.ATTCKConfVersion, error) {
	ruleData, err := dal.LoadATTCKConfData(ctx, h.db.Get())
	if err != nil {
		return nil, err
	}

	return &ruleData.ATTCKConfVersion, nil
}

func (h *ATTCKHandler) GetATTCKVersionHistory(ctx context.Context, offset, limit int, v string) (int64, []*model.ATTCKConfVersion, error) {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	return dal.LoadATTCKConfVersions(ctx, h.db.Get(), offset, limit, v)
}

func (h *ATTCKHandler) GetATTCKVersionList(ctx context.Context) []*model.ATTCKConfVersion {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	versions := make([]*model.ATTCKConfVersion, 0)
	clusters := make([]model.TensorCluster, 0)
	err := h.db.Get().WithContext(ctx).Model(new(model.TensorCluster)).Find(&clusters).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("query ivan_assets_clusters fails")
		return versions
	}
	clustersMap := make(map[string]struct{})
	for i := range clusters {
		clustersMap[clusters[i].RuleVersion] = struct{}{}
	}
	for i := range h.rules {
		if _, ok := clustersMap[h.rules[i].currentVersion.VString()]; !ok {
			continue
		}
		versions = append(versions, h.rules[i].currentVersion)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version1 > versions[j].Version1
	})
	return versions
}

func (h *ATTCKHandler) GetATTCKConfData(ctx context.Context, reqBaseOffset, reqOnlineOffset uint64, v uint16) (*model.LatestATTCKRuleInfo, error) {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	vRules, ok := h.rules[v]
	if !ok {
		return nil, ErrInvalidRulesVersion1
	}

	latestBaseOffset := vRules.baseOffset
	latestOnlineOffset := vRules.onlineOffset
	var info = &model.LatestATTCKRuleInfo{
		LatestDataVersion:    int64(latestBaseOffset),
		LatestSettingVersion: int64(latestOnlineOffset),
	}
	if latestBaseOffset > reqBaseOffset {
		got := false
		if v == 2 {
			outputBytes, ok := h.rulesManager.GetOutputBytes()
			if ok {
				info.DataChanged = true
				info.Data = string(outputBytes)
				got = true
			}
		}
		if !got {
			data, err := dal.LoadATTCKConfDataByVersion1(ctx, h.db.GetReadDB(), v)
			if err != nil {
				return nil, err
			}

			info.DataChanged = true
			info.Data = base64.StdEncoding.EncodeToString(data.Content)
		}

	}

	if latestOnlineOffset > reqOnlineOffset {
		info.SettingChanged = true
		for _, rule := range vRules.sortedItems {
			if rule.disabled {
				info.ClosedRules = append(info.ClosedRules, rule.name)
			}
		}
	}
	return info, nil
}

const (
	flushInterval = time.Second * 60
)

func (h *ATTCKHandler) asyncLoop() {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for range ticker.C {
		for i := 1; i <= currentRulesVersion; i++ {
			h.flushCache(uint16(i))
		}
	}
}

func (h *ATTCKHandler) flushCache(v uint16) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), flushInterval)
	defer cancel()
	latestOffset, latestOnlineOffset, err := h.getLatestVersion(ctx, v)
	if err != nil {
		logging.Get().Err(err).Msg("LoadATTCKConfVersion fail")
		return
	}

	pendingUpdates := false
	if v >= 2 {
		var cerr error
		pendingUpdates, cerr = h.rulesManager.CheckCustomConfigsUpdates(ctx)
		if cerr != nil {
			logging.Get().Err(cerr).Msg("CheckCustomConfigsPending error")
		}
		if !pendingUpdates {
			pendingUpdates = true
		}
	}

	vRules, _ := h.rules[v]
	if pendingUpdates {
		logging.Get().Info().Bool("pendingCConfigsToReload", pendingUpdates).Msgf(
			"updateTriggerCustomConfigsPending baseOffset:%d, onlineOffset:%d, latestOffset:%d, latestOnlineOffset:%d",
			vRules.baseOffset, vRules.onlineOffset, latestOffset, latestOnlineOffset)
		if err = h.updateConfigs(ctx, v, updateTriggerCustomConfigsPending); err != nil {
			logging.Get().Err(err).Msg("load fail when updateTriggerCustomConfigsPending")
		}
	} else if latestOffset > vRules.baseOffset {
		logging.Get().Info().Bool("pendingCConfigsToReload", pendingUpdates).Msgf(
			"updateTriggerRulesUpdated baseOffset:%d, onlineOffset:%d, latestOffset:%d, latestOnlineOffset:%d",
			vRules.baseOffset, vRules.onlineOffset, latestOffset, latestOnlineOffset)
		if err = h.updateConfigs(ctx, v, updateTriggerRulesUpdated); err != nil {
			logging.Get().Err(err).Msg("load fail when updateTriggerRulesUpdated")
		}
	} else if latestOnlineOffset > vRules.onlineOffset {
		logging.Get().Info().Bool("pendingCConfigsToReload", pendingUpdates).Msgf(
			"updateTriggerSwitchUpdated baseOffset:%d, onlineOffset:%d, latestOffset:%d, latestOnlineOffset:%d",
			vRules.baseOffset, vRules.onlineOffset, latestOffset, latestOnlineOffset)

		if err = h.updateConfigs(ctx, v, updateTriggerSwitchUpdated); err != nil {
			logging.Get().Err(err).Msg("load fail when updateTriggerSwitchUpdated")
		}
	}
}

func (h *ATTCKHandler) getLatestVersion(ctx context.Context, v uint16) (uint64, uint64, error) {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	latestOffset, err := dal.LoadATTCKConfVersion(ctx, h.db.GetReadDB(), v)
	if err != nil {
		logging.Get().Err(err).Msg("LoadATTCKConfVersion fail")
		return 0, 0, err
	}

	latestOnlineOffset, err := dal.LoadATTCKRuleMaskVersion(ctx, h.db.GetReadDB(), v)
	if err != nil {
		logging.Get().Err(err).Msg("LoadATTCKRuleMaskVersion fail")
		return 0, 0, err
	}
	return latestOffset, latestOnlineOffset, err
}

func (h *ATTCKHandler) updateV1RuleVersion(ctx context.Context, v string) {
	// rule_version为空时也更新，原因是初始化数据时无法区分哪些集群时老版本。新集群可能会有几十秒的数据错误，当新集群成功启动并注册后，会更新自己的记录。
	err := h.db.Get().WithContext(ctx).Model(&model.TensorCluster{}).Where("rule_version = '' or rule_version is NULL or rule_version like 'v1.%'").Updates(map[string]interface{}{"rule_version": v}).Error
	if err != nil {
		logging.Get().Error().Err(err).Msg("update ivan_assets_clusters.rule_version fails")
	}
}

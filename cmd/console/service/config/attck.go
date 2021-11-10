package config

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/go-redsync/redsync/v4"
	"github.com/go-redsync/redsync/v4/redis/goredis/v8"

	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"

	"gopkg.in/yaml.v2"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ATTCKHandler struct {
	db             *rdbtools.GormWrapper
	currentVersion *model.ATTCKConfVersion
	items          map[string]*ruleItem
	sortedItems    []*ruleItem
	cacheLock      sync.RWMutex
	baseOffset     uint32
	onlineOffset   uint32
	rs             *redsync.Redsync
}

type ruleItem struct {
	name        string
	ruleType    string
	description string
	severity    uint8
	hthreats    uint8
	adapter     map[string]map[string]string
	disabled    bool
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
	ErrInvalidRuleData = errors.New("invalid rule data")
)

func parseItems(data []byte) (version string, rules map[string]*ruleItem, err error) {
	header, rulesContext, _, err := cryption.ReadRulesData(data)
	if err != nil {
		logging.GetLogger().Warn().Msgf("decode rule data fail, err:%s", err.Error())
		return "", nil, ErrInvalidRuleData
	}
	version = fmt.Sprintf("v%d.%d", header.Version[0], header.Version[1])

	var fDataRules []model.RuleFromYaml
	rules = make(map[string]*ruleItem)
	err = yaml.Unmarshal(rulesContext, &fDataRules)
	if err != nil {
		logging.GetLogger().Warn().Msgf("unmarshal rule fail, err:%s", err.Error())
		return "", nil, ErrInvalidRuleData
	}
	for _, item := range fDataRules {
		if len(item.Rule) == 0 || len(item.Priority) == 0 {
			continue
		}

		ruleType, err := model.GetInfoFromOutput("rule_type=", item.Output)
		if err != nil {
			ruleType = "Other"
		}
		ruleTypeZh := model.TranslateRuleType(ruleType)
		descZh := ""
		zhMsg, err := model.GetInfoFromOutput("zh_msg=", item.Output)
		if err != nil {
			continue
		}

		if len(strings.Split(zhMsg, ";")) < 2 {
			descZh = strings.Split(zhMsg, ";")[0]
		} else {
			descZh = strings.Split(zhMsg, ";")[1]
		}

		tsAdapter := make(map[string]map[string]string)
		tsAdapter[string(lang.LanguageZH)] = make(map[string]string)
		tsAdapter[string(lang.LanguageZH)][typeKey] = ruleTypeZh
		tsAdapter[string(lang.LanguageZH)][descriptionKey] = descZh

		rules[item.Rule] = &ruleItem{
			name:        item.Rule,
			description: item.Desc,
			severity:    model.Str2SeverityNum(item.Priority),
			hthreats:    item.Hthreats,
			ruleType:    ruleType,
			adapter:     tsAdapter,
		}
	}
	return version, rules, nil
}

func NewATTCKHandler(db *rdbtools.GormWrapper, redisCli *redis.Client) (*ATTCKHandler, error) {
	handler := &ATTCKHandler{
		db:    db,
		items: make(map[string]*ruleItem),
		rs:    redsync.New(goredis.NewPool(redisCli)),
	}

	err := handler.loadFromStore()
	if err != nil {
		return nil, err
	}

	go handler.asyncLoop()
	return handler, nil
}

func (h *ATTCKHandler) loadFromStore() error {
	h.cacheLock.Lock()
	defer h.cacheLock.Unlock()
	const (
		loadTimeout = time.Second * 5
	)
	ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
	defer cancel()
	conf, err := dal.LoadATTCKConfData(ctx, h.db.Get())
	if err != nil {
		if err == dal.ErrATTCKConfDataNotFound {
			logging.GetLogger().Warn().Msgf("attck conf not found")
			h.baseOffset = 0
			h.onlineOffset = 0
			return nil
		}
		return err
	}

	_, rules, err := parseItems(conf.Content)
	if err != nil {
		return err
	}

	onlineOffset, err := dal.LoadATTCKRuleMaskVersion(ctx, h.db.Get())
	if err != nil {
		return err
	}

	ruleMasks, err := dal.LoadATTCKRuleMasks(ctx, h.db.Get())
	if err != nil {
		return err
	}

	h.updateRules(rules)
	h.baseOffset = conf.ID
	h.onlineOffset = onlineOffset
	h.currentVersion = &model.ATTCKConfVersion{
		Version:   conf.Version,
		Username:  conf.Username,
		CreatedAt: conf.CreatedAt,
	}

	logging.GetLogger().Info().Msgf("baseOffset:%d, onlineOffset:%d", h.baseOffset, h.onlineOffset)
	for _, mask := range ruleMasks {
		if item := h.items[mask.Name]; item != nil {
			item.disabled = true
		}
	}

	return nil
}

const (
	attckLockKey = "attck-lock"
)

func (h *ATTCKHandler) obtainLock(ctx context.Context, mutex *redsync.Mutex) error {
	if err := mutex.LockContext(ctx); err != nil {
		logging.GetLogger().Err(err).Msg("obtain attck lock fail")
		return err
	}

	return nil
}

func (h *ATTCKHandler) releaseLock(mutex *redsync.Mutex) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	if ok, err := mutex.UnlockContext(ctx); err != nil || !ok {
		logging.GetLogger().Err(err).Msg("release attck lock fail")
	}
}

func (h *ATTCKHandler) UpdateConfig(ctx context.Context, username string, data []byte) (*model.ATTCKRuleData, error) {
	mutex := h.rs.NewMutex(attckLockKey)
	if err := h.obtainLock(ctx, mutex); err != nil {
		return nil, err
	}

	defer h.releaseLock(mutex)
	h.flushCache()
	version, rules, err := parseItems(data)
	if err != nil {
		return nil, err
	}

	h.cacheLock.Lock()
	defer h.cacheLock.Unlock()
	var deprecatedRuleMasks []string
	for _, rule := range h.items {
		if rule.disabled && rules[rule.name] != nil {
			// set disabled
			rules[rule.name].disabled = true
		}

		if _, ok := rules[rule.name]; !ok && rule.disabled {
			// deprecated ruleMasks
			deprecatedRuleMasks = append(deprecatedRuleMasks, rule.name)
		}
	}

	nowTime := time.Now()
	confVersion := model.ATTCKConfVersion{
		Username:  username,
		Version:   version,
		CreatedAt: nowTime,
	}
	attckRuleData := &model.ATTCKRuleData{
		ATTCKConfVersion: confVersion,
		Content:          data,
	}

	baseOffset, err := dal.SaveATTCKConfData(ctx, h.db.Get(), attckRuleData, deprecatedRuleMasks)
	if err != nil {
		return nil, err
	}

	h.baseOffset = baseOffset
	h.currentVersion = &confVersion
	h.updateRules(rules)
	if len(deprecatedRuleMasks) > 0 {
		h.onlineOffset++
	}

	return attckRuleData, nil
}

func (h *ATTCKHandler) updateRules(rules map[string]*ruleItem) {
	h.items = rules
	h.sortedItems = make([]*ruleItem, 0, len(rules))
	for _, rule := range rules {
		h.sortedItems = append(h.sortedItems, rule)
	}
	sort.Slice(h.sortedItems, func(i, j int) bool {
		return compare(h.sortedItems[i], h.sortedItems[j])
	})
}

type GetRuleListArg struct {
	Offset         int
	Limit          int
	SeverityFilter map[uint8]struct{}
	HthreatsFilter map[uint8]struct{}
	Query          string
	Lang           string
}

func (h *ATTCKHandler) GetRuleList(_ context.Context, arg *GetRuleListArg) (int64, []*model.ATTCKRuleDisplay, error) {
	h.flushCache()
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	var items []*ruleItem
	var total int64
	var offset = arg.Offset
	for _, rule := range h.sortedItems {
		if (arg.Query == "" || checkRuleMatchQuery(rule, arg.Query, arg.Lang)) &&
			(len(arg.SeverityFilter) == 0 || checkSeverityFilter(rule, arg.SeverityFilter)) &&
			(len(arg.HthreatsFilter) == 0 || checkHthreatsFilter(rule, arg.HthreatsFilter)) {
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

func (h *ATTCKHandler) UpdateRuleSettings(ctx context.Context, settings []*model.ATTCKRuleSwitch) ([]*model.ATTCKRuleSwitch, error) {
	mutex := h.rs.NewMutex(attckLockKey)
	if err := h.obtainLock(ctx, mutex); err != nil {
		return nil, err
	}
	defer h.releaseLock(mutex)

	h.flushCache()
	h.cacheLock.Lock()
	defer h.cacheLock.Unlock()

	var deletedMasks = make(map[string]struct{})
	var addMasks = make(map[string]struct{})
	for _, setting := range settings {
		item := h.items[setting.Name]
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
			Name: mask,
		})
	}

	if len(deletedMasks) > 0 || len(addMasks) > 0 {
		if err := dal.UpdateRuleMask(ctx, h.db.Get(), masks, util.StringSetToArray(deletedMasks)); err != nil {
			return nil, err
		}
		for _, setting := range settings {
			h.items[setting.Name].disabled = !setting.Enabled
		}
		h.onlineOffset++
	}

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

func (h *ATTCKHandler) GetATTCKVersion(_ context.Context) (*model.ATTCKConfVersion, error) {
	h.flushCache()
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	if h.currentVersion != nil {
		return h.currentVersion, nil
	}

	return nil, dal.ErrATTCKConfDataNotFound
}

func (h *ATTCKHandler) GetATTCKVersionHistory(ctx context.Context, offset, limit int) (int64, []*model.ATTCKConfVersion, error) {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	return dal.LoadATTCKConfVersions(ctx, h.db.Get(), offset, limit)
}

func (h *ATTCKHandler) GetATTCKConfData(ctx context.Context, reqBaseOffset, reqOnlineOffset uint32) (*model.LatestATTCKRuleInfo, error) {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	latestBaseOffset := h.baseOffset
	latestOnlineOffset := h.onlineOffset
	var info = &model.LatestATTCKRuleInfo{
		LatestDataVersion:    latestBaseOffset,
		LatestSettingVersion: latestOnlineOffset,
	}
	if latestBaseOffset > reqBaseOffset {
		data, err := dal.LoadATTCKConfData(ctx, h.db.Get())
		if err != nil {
			return nil, err
		}

		info.DataChanged = true
		info.Data = base64.StdEncoding.EncodeToString(data.Content)
	}

	if latestOnlineOffset > reqOnlineOffset {
		info.SettingChanged = true
		for _, rule := range h.sortedItems {
			if rule.disabled {
				info.ClosedRules = append(info.ClosedRules, rule.name)
			}
		}
	}

	return info, nil
}

const (
	flushInterval = time.Second * 10
)

func (h *ATTCKHandler) asyncLoop() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for range ticker.C {
		h.flushCache()
	}
}

func (h *ATTCKHandler) flushCache() {
	ctx, cancel := context.WithTimeout(context.Background(), flushInterval)
	defer cancel()
	latestOffset, latestOnlineOffset, err := h.getLatestVersion(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msg("LoadATTCKConfVersion fail")
		return
	}

	if latestOffset > h.baseOffset || latestOnlineOffset > h.onlineOffset {
		logging.GetLogger().Info().Msgf(
			"baseOffset:%d, onlineOffset:%d, latestOffset:%d, latestOnlineOffset:%d",
			h.baseOffset, h.onlineOffset, latestOffset, latestOnlineOffset)
		if err = h.loadFromStore(); err != nil {
			logging.GetLogger().Err(err).Msg("load fail")
		}
	}
}

func (h *ATTCKHandler) getLatestVersion(ctx context.Context) (uint32, uint32, error) {
	h.cacheLock.RLock()
	defer h.cacheLock.RUnlock()
	latestOffset, err := dal.LoadATTCKConfVersion(ctx, h.db.Get())
	if err != nil {
		logging.GetLogger().Err(err).Msg("LoadATTCKConfVersion fail")
		return 0, 0, err
	}

	latestOnlineOffset, err := dal.LoadATTCKRuleMaskVersion(ctx, h.db.Get())
	if err != nil {
		logging.GetLogger().Err(err).Msg("LoadATTCKRuleMaskVersion fail")
		return 0, 0, err
	}
	return latestOffset, latestOnlineOffset, err
}

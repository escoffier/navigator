package attck

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	ctxKeyConfigValues = "CTX_CCONFIG_DATA"
)

var (
	ErrEmptyValue = errors.New("values not set")
)

type ManagerBuilder struct {
	encoder Encoder
	plugins []ProcessPlugin

	db *databases.RDBInstance
}
type RawData struct {
	Data    []byte
	Version [2]uint16
}
type Encoder func(ctx context.Context, before RawData) ([]byte, error)

func NewManagerBuilder(db *databases.RDBInstance) *ManagerBuilder {
	return &ManagerBuilder{
		db: db,
	}
}

func (b *ManagerBuilder) getCustomConfigs(ctx context.Context) ([]CconfigItem, error) {
	v := ctx.Value(ctxKeyConfigValues)
	if v == nil {
		return nil, ErrEmptyValue
	}
	switch vt := v.(type) {
	case error:
		logging.Get().Err(vt).Msg("get custom configs error")
		return nil, vt
	case []*model.AttckCustomConfig:
		ret := make([]CconfigItem, len(vt))
		for i, c := range vt {
			ret[i].CconfigKey = c.CconfigKey
			ret[i].RuleKey = c.RuleKey
			var vals []string
			jerr := json.Unmarshal([]byte(c.CconfigValue), &vals)
			if jerr != nil {
				logging.Get().Err(jerr).Str("v", c.CconfigValue).Msg("json unmarshal error")
				continue
			}
			ret[i].Values = vals
		}
		return ret, nil
	default:
		return nil, ErrEmptyValue
	}
}
func (b *ManagerBuilder) InitPlugins() error {
	pocPlugin := newPocSwitchPluginWithGiven(os.Getenv(EnvKeyDPTags))

	b.plugins = append(b.plugins, pocPlugin)

	ccPlugin := NewCustomConfigPlugin(b.getCustomConfigs)
	b.plugins = append(b.plugins, ccPlugin)

	return nil
}

func (m *ManagerBuilder) SetEncoder(enc Encoder) {
	m.encoder = enc
}
func (m *ManagerBuilder) Build() *RulesManager {
	return &RulesManager{
		encoder:      m.encoder,
		plugins:      m.plugins,
		db:           m.db,
		rulesSession: new(atomic.Pointer[sessionInfo]),
	}
}

type sessionInfo struct {
	rulesStore  *RulesStore
	processor   *Processor
	pctx        PluginContext
	outputBytes []byte
	version     [2]uint16
}
type RulesManager struct {
	encoder Encoder
	plugins []ProcessPlugin
	db      *databases.RDBInstance

	rulesSession *atomic.Pointer[sessionInfo]
}

func (m *RulesManager) GetRulesTmp() ([]*model.RuleFromYaml, error) {
	return nil, nil
}

func (m *RulesManager) GetOutputBytes() ([]byte, bool) {
	rs := m.rulesSession.Load()
	if rs == nil {
		return nil, false
	}
	return rs.outputBytes, true
}

func (m *RulesManager) initCconfigs(ctx context.Context, iconfs []*CconfigInitConfig, store *RulesStore) error {
	for _, iconf := range iconfs {
		for _, steps := range iconf.RulesAppliedSteps {
			if len(steps) == 0 {
				logging.Get().Warn().Msg("steps exception")
				continue
			}
			r, exist := store.GetRule(ctx, steps[0])

			rcat := ""
			if exist {
				rcat = r.Category[string(lang.LanguageEN)]
			}

			cc := model.AttckCustomConfig{
				RuleKey:      steps[0],
				RuleCategory: rcat,
				CconfigKey:   iconf.Key,
				CconfigValue: "",
				Creator:      "system",
				CreatedAt:    time.Now().Unix(),
				Updater:      "system",
				UpdatedAt:    time.Now().Unix(),
				Status:       model.StatusDeleted,
			}
			_, err := dal.CreateCustomConfig(context.Background(), m.db.Get(), &cc)
			if err != nil {
				logging.Get().Err(err).Interface("data", m).Msg("create error")
				return err
			}
		}

	}
	return nil
}

func (m *RulesManager) getStore(ctx context.Context) (*RulesStore, bool) {
	rs := m.rulesSession.Load()
	if rs == nil {
		return nil, false
	}
	return rs.rulesStore, true
}
func (m *RulesManager) getCustomInitConfigs(ctx context.Context) ([]*CconfigInitConfig, bool) {
	rs := m.rulesSession.Load()
	if rs == nil {
		return nil, false
	}
	return rs.rulesStore.GetCconfigInitConfigs(), true
}

func (m *RulesManager) getRule(ctx context.Context, ruleKey string) (*HolmesRule, bool) {
	if len(ruleKey) == 0 {
		return nil, false
	}
	rs := m.rulesSession.Load()
	if rs == nil {
		return nil, false
	}
	return rs.rulesStore.GetRule(ctx, ruleKey)
}

func loadCustomConfigs(ctx context.Context, db *databases.RDBInstance) ([]*model.AttckCustomConfig, error) {
	qopt := dal.NewCustomConfigsOption()
	qopt.WithIn("status", []model.CconfigStatus{model.StatusOK, model.StatusPending})

	count, err := dal.CountCustomConfigs(ctx, db.GetReadDB(), qopt, nil)
	if err != nil {
		logging.Get().Err(err).Msg("get custom configs count error")
		return nil, err
	}
	configs := make([]*model.AttckCustomConfig, 0, count)
	for page := 0; len(configs) < count; page++ {

		pageConfigs, perr := dal.GetCustomConfigs(ctx, db.GetReadDB(), qopt, nil, 50, page*50)
		if perr != nil {
			logging.Get().Err(perr).Int("page", page).Msg("get custom configs error")
			return nil, perr
		}
		configs = append(configs, pageConfigs...)
	}
	return configs, nil
}

func (m *RulesManager) updateCustomConfigsStatus(ctx context.Context) error {
	opt := dal.NewCustomConfigsOption()
	opt.WithEqual("status", model.StatusPending)
	return dal.SetCustomConfigStatus(ctx, m.db.Get(), opt, model.StatusOK)
}

func (m *RulesManager) CheckCustomConfigsPending(ctx context.Context) (bool, error) {
	opt := dal.NewCustomConfigsOption()
	opt.WithEqual("status", model.StatusPending)
	count, err := dal.CountCustomConfigs(ctx, m.db.GetReadDB(), opt, nil)
	return count > 0, err
}

func (m *RulesManager) UpdateRules(ctx context.Context, rawData []byte, version [2]uint16) (output RawData, ccVersion uint64, err error) {
	var raw RawData
	raw.Data = rawData
	raw.Version = version

	configs, err := loadCustomConfigs(ctx, m.db)
	if err != nil {
		logging.Get().Err(err).Msg("load custom configs error")
		return RawData{}, 0, err
	}
	ccUpdatedLatest := int64(0)
	for _, c := range configs {
		if c.Status == model.StatusDeleted {
			continue
		}
		if c.UpdatedAt > ccUpdatedLatest {
			ccUpdatedLatest = c.UpdatedAt
		}
	}
	ctx = context.WithValue(ctx, ctxKeyConfigValues, configs)

	processor, infoStore, err := ProcessorBuilder(ctx, raw.Data)
	if err != nil {
		logging.Get().Err(err).Msg("processor build error")
		return RawData{}, 0, err
	}
	for _, p := range m.plugins {
		processor.AddPlugin(p)
	}

	ierr := m.initCconfigs(ctx, infoStore.GetCconfigInitConfigs(), infoStore)
	if ierr != nil {
		logging.Get().Err(ierr).Msg("init cconfigs error")
	}
	logging.Get().Info().Int("rules num", len(infoStore.rmap)).Int("conf num", len(infoStore.configsInit)).Msg("processor build OK")

	ruleBytes, pctx, procErr := processor.Process(ctx)
	if procErr != nil {
		logging.Get().Err(procErr).Msg("process error")
		return RawData{}, 0, procErr
	}
	raw.Data = ruleBytes

	after, eerr := m.encoder(ctx, raw)
	if eerr != nil {
		logging.Get().Err(eerr).Msg("encode error")
		return RawData{}, 0, eerr
	}

	newSession := sessionInfo{
		rulesStore:  infoStore,
		processor:   processor,
		pctx:        pctx,
		outputBytes: after,
		version:     raw.Version,
	}
	m.rulesSession.Store(&newSession)

	if err := m.updateCustomConfigsStatus(ctx); err != nil {
		logging.Get().Err(err).Msg("update custom configs status error")
	}
	return raw, uint64(ccUpdatedLatest), nil
}

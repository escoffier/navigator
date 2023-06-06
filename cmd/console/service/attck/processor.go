package attck

import (
	"bytes"
	"context"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/holmes"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	gmodel "gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/mozart"
	"gopkg.in/yaml.v2"
)

type HolmesRule struct {
	gmodel.UserRuleYaml
	isInternal bool
}

func GetFromHola(m gmodel.ConfigMozartInfoLang, lang string) string {
	switch lang {
	case "en":
		return m.En
	case "zh":
		return m.Zh
	default:
		return m.Zh
	}
}

type RulesStore struct {
	rules       []*HolmesRule
	rmap        map[string]*HolmesRule
	configsInit []*holmes.CconfigInitConfig
}

func (s *RulesStore) GetCconfigInitConfigs() []*holmes.CconfigInitConfig {
	return s.configsInit
}
func (s *RulesStore) ISearch(ctx context.Context, kw string) ([]*HolmesRule, error) {
	candidates := make([]*HolmesRule, 0, 3)
	for _, r := range s.rules {
		if r.isInternal {
			continue
		}

		if strings.Contains(strings.ToLower(r.Info.Name.En), strings.ToLower(kw)) {
			candidates = append(candidates, r)
			break
		}
		if strings.Contains(r.Info.Name.Zh, kw) {
			candidates = append(candidates, r)
			break
		}
	}
	return candidates, nil
}

func (s *RulesStore) GetRule(ctx context.Context, ruleKey string) (*HolmesRule, bool) {
	r, exist := s.rmap[ruleKey]
	return r, exist
}

func (s *RulesStore) addRule(r *HolmesRule) {
	s.rules = append(s.rules, r)
	s.rmap[r.Key] = r
}
func (s *RulesStore) setCconfigInit(init []*holmes.CconfigInitConfig) {
	s.configsInit = init
}

func newStore() *RulesStore {
	return &RulesStore{
		rules: make([]*HolmesRule, 0, 110),
		rmap:  make(map[string]*HolmesRule, 110),
	}
}

type mlTmp struct {
	Macro     string `yaml:"macro"`
	Condition string `yaml:"condition"`
	List      string `yaml:"list"`
	Items     []any  `yaml:"items"`
}
type ProcessPlugin interface {
	Name() string
	GetSession(ctx context.Context, pctx PluginContext) (PluginSession, error)
}
type PluginSession interface {
	Name() string
	ProcessRule(ctx context.Context, r gmodel.UserRuleYaml) (after *gmodel.UserRuleYaml, changed bool, err error) // There could be changes on the rules format. We don't use yaml to parse.
	ProcessMacro(ctx context.Context, m holmes.Macro) (after *holmes.Macro, changed bool, err error)
	ProcessList(ctx context.Context, l holmes.List) (after *holmes.List, changed bool, err error)
	NextRule(ctx context.Context) (r *gmodel.UserRuleYaml, more bool)
	NextMacro(ctx context.Context) (after *holmes.Macro, more bool)
	NextList(ctx context.Context) (after *holmes.List, more bool)
}

type PluginContext struct {
	macros []*holmes.Macro
	lists  []*holmes.List
	rules  []*gmodel.UserRuleYaml

	configs []*holmes.CconfigInitConfig
}

func (c *PluginContext) GetRule(ctx context.Context, ruleKey string) (*gmodel.UserRuleYaml, bool) {
	for _, r := range c.rules {
		if r.Key == ruleKey {
			return r, true
		}
	}
	return nil, false
}
func (c *PluginContext) GetMacro(ctx context.Context, macro string) (*holmes.Macro, bool) {
	for _, m := range c.macros {
		if m.Macro == macro {
			return m, true
		}
	}
	return nil, false
}
func (c *PluginContext) GetList(ctx context.Context, list string) (*holmes.List, bool) {
	for _, l := range c.lists {
		if l.List == list {
			return l, true
		}
	}
	return nil, false
}
func (c *PluginContext) GetCustomConfigs(ctx context.Context) ([]*holmes.CconfigInitConfig, bool) {
	return c.configs, true
}

type RawRule struct {
	key   string
	lines []string
}
type Processor struct {
	plugins []ProcessPlugin

	// original
	parsed holmes.ItemsParsed
}

func (p *Processor) AddPlugin(pp ProcessPlugin) error {
	p.plugins = append(p.plugins, pp)
	return nil
}

func (p *Processor) Process(ctx context.Context) ([]byte, PluginContext, error) {
	pctx := PluginContext{
		macros:  p.parsed.Macros,
		lists:   p.parsed.Lists,
		configs: p.parsed.CustomConfigInits,
		rules:   p.parsed.Rules,
	}

	psessions := make([]PluginSession, 0, len(p.plugins))
	for _, p := range p.plugins {
		ps, err := p.GetSession(ctx, pctx)
		if err != nil {
			logging.Get().Err(err).Msg("get session of plugin error")
			continue
		}
		psessions = append(psessions, ps)
	}

	newLists := make([]*holmes.List, 0, len(pctx.lists))
	for _, list := range pctx.lists {
		for _, ps := range psessions {
			newList, changed, pperr := ps.ProcessList(ctx, *list)
			if pperr != nil {
				logging.Get().Err(pperr).Str("plugin", ps.Name()).Interface("list", *list).Msg("plugin process list error")
				continue
			} else if changed {

				if newList != nil {
					list = newList
					sb := strings.Builder{}
					for _, item := range newList.Items {
						sb.WriteString(item)
						sb.WriteByte(',')
					}
					logging.Get().Info().Str("plugin", ps.Name()).Str("items", sb.String()).Msg("plugin process list done")
				} else {
					list = nil
					logging.Get().Info().Str("plugin", ps.Name()).Msg("plugin process list remove done")
					break
				}
			}
		}
		if list != nil {
			newLists = append(newLists, list)
		}
	}
	pctx.lists = newLists

	newMacros := make([]*holmes.Macro, 0, len(pctx.macros))
	for _, macro := range pctx.macros {
		for _, ps := range psessions {
			newMacro, changed, pperr := ps.ProcessMacro(ctx, *macro)
			if pperr != nil {
				logging.Get().Err(pperr).Str("plugin", ps.Name()).Interface("macro", *macro).Msg("plugin process macro error")
				continue
			} else if changed {
				logging.Get().Info().Str("plugin", ps.Name()).Msg("plugin process macro done")
				if newMacro != nil {
					macro = newMacro
				} else {
					macro = nil
					break
				}
			}
		}
		if macro != nil {
			newMacros = append(newMacros, macro)
		}
	}
	pctx.macros = newMacros

	newRules := make([]*gmodel.UserRuleYaml, 0, len(pctx.rules))
	for _, rule := range pctx.rules {
		for _, ps := range psessions {
			newRule, changed, pperr := ps.ProcessRule(ctx, *rule)
			if pperr != nil {
				logging.Get().Err(pperr).Str("plugin", ps.Name()).Str("rule", rule.Key).Msg("plugin process rule error")
				continue
			} else if changed {
				logging.Get().Info().Str("plugin", ps.Name()).Str("rkey", rule.Key).Msg("plugin process rule done")
				if newRule != nil {
					rule = newRule
				} else {
					rule = nil
					break
				}
			}
		}
		if rule != nil {
			newRules = append(newRules, rule)
		}
	}
	pctx.rules = newRules

	for _, ps := range psessions {
		for i := 0; i < 1000; i++ {
			nextList, more := ps.NextList(ctx)
			if nextList != nil {
				pctx.lists = append(pctx.lists, nextList)
			}
			if !more {
				break
			}
		}
		for i := 0; i < 1000; i++ {
			nextMacro, more := ps.NextMacro(ctx)
			if nextMacro != nil {
				pctx.macros = append(pctx.macros, nextMacro)
			}
			if !more {
				break
			}
		}

		for i := 0; i < 1000; i++ {
			nextRule, more := ps.NextRule(ctx)
			if nextRule != nil {
				pctx.rules = append(pctx.rules, nextRule)
			}
			if !more {
				break
			}
		}
	}

	outputBui := bytes.Buffer{}
	rbytes, err := yaml.Marshal(pctx.rules)
	if err != nil {
		return nil, pctx, err
	}
	outputBui.Write(rbytes)

	mbytes, err := yaml.Marshal(pctx.macros)
	if err != nil {
		return nil, pctx, err
	}
	outputBui.Write(mbytes)

	lbytes, err := yaml.Marshal(pctx.lists)
	if err != nil {
		return nil, pctx, err
	}
	outputBui.Write(lbytes)

	outputBytes := outputBui.Bytes()

	return outputBytes, pctx, nil
}

func ProcessorBuilder(ctx context.Context, decodedRaw []byte) (*Processor, *RulesStore, error) {
	parsed, err := holmes.ParseHolmesFile(decodedRaw)
	if err != nil {
		logging.Get().Err(err).Msg("parse holmes file error")
		return nil, nil, err
	}

	store := newStore()
	store.setCconfigInit(parsed.CustomConfigInits)

	for _, r := range parsed.Rules {
		if r.Key == "" {
			continue
		}
		if r.Condition == "" || mozart.IsURMozartMarco(*r) { // filter out mozart branch item
			continue
		}
		isInternal := false
		// 只是关联规则，不应展示，，是内部规则
		if util.ContainsString(r.Info.Tags, "related") {
			isInternal = true
		}

		ruleItem := HolmesRule{
			isInternal: isInternal,
		}
		ruleItem.UserRuleYaml = *r
		store.addRule(&ruleItem)
	}
	proc := &Processor{
		plugins: make([]ProcessPlugin, 0, 5),
		parsed:  parsed,
	}
	return proc, store, nil
}
